"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

nm_event_handler.py

Python lambda script to handle CloudFormation and EventBridge events for changes. This script relies on environment variables to pass in how
things should be configured. These are normally set by the CloudFormation template wrapping this script. Those variables are:

STACK_ARN - The CloudFormation stack ARN used for this deployment
GLOBAL_NETWORK_ARN - The global network ARN (arn:aws:networkmanager::accountid:global-network/global-network-0123456789abcdef) of the network to monitor.
METRIC_NAMES - Comma-separated list of metrics to alarm on. ex: "BytesIn,BytesOut"
STDDEV - By how many standard deviations should the anomaly detection threshold be set to, ex: "2"
MINUTES - How many minutes should the anomalies be occurring for before we alarm and start the capturing?, ex: "2"
MINIMUM_VALUE - At very low usages, the standard deviation alarm will trigger on very low amounts. This parameter defines how many bytes per minute an 
                attachment must have before we consider triggering on the detection threshold.
SNS_TOPIC - The SNS topic ARN to send notifications to
OBJECTS_NAME - A short unique string to add to all names (S3 buckets, Lambda functions, Alarm names) to uniquely identify this deployment.
ALARM_LAMBDA_ROLE - The IAM Role ARN to be used for the alarm-handling lambda functions

Additionally, it leverages some variables set by AWS Lambda itself - AWS_LAMBDA_FUNCTION_NAME and AWS_REGION.
"""
import boto3
import boto3.exceptions
import botocore
import botocore.exceptions
import cfnresponse
import logging
import threading
import os
import re
import urllib.request
from typing import Dict, List, Set, Any, Optional

# 'tgw' or 'cwan' -> regions -> TGW or core network ID -> attachment ID -> dict of data (type:attachment Type, alarms if find_alarms has been called)
type AttachmentData = dict[str, dict[str, dict[str, dict[str, dict[str, Any]]]]]

def timeout(event, context):
    """
    If we run over the lambda invocation time limit, this function is called. If we're called from CloudFormation, it sends the failed status back 
    to keep CloudFormation from waiting longer.
    """
    if 'ResponseURL' in event:
        logging.error('Execution is about to time out, sending failure response to CloudFormation')
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, None)
    exit(1)


def find_attachments() -> AttachmentData:
    """
    Find all TGW and CloudWAN attachments in this global network. This function can be relatively slow if a lot of TGW regions are in use. It filters
    to only attachments that are available (fully working). Transit Gateway peering connections are also ignored (we will catch the traffic coming into 
    transit gateway via whatever downstream connection).

    :return AttachmentData: Filled in AttachmentData, see description of type.
    """
    ret:AttachmentData = {"tgw": {}, "cwan": {}}

    # Find all Transit Gateway attachments. This requires cross-region calls, so batch together all TGWs in a region, then do one call per region.
    nm = boto3.client('networkmanager')
    tgws_by_region:dict[str, list[str]] = {}
    global_network_id = os.environ['GLOBAL_NETWORK_ARN'].split('/')[1]
    for tgw in nm.get_transit_gateway_registrations(GlobalNetworkId=global_network_id)['TransitGatewayRegistrations']:
        if 'TransitGatewayArn' in tgw:
            tgw_region = tgw['TransitGatewayArn'].split(':')[3]
            if tgw_region not in tgws_by_region:
                tgws_by_region[tgw_region] = []
            tgws_by_region[tgw_region].append(tgw['TransitGatewayArn'].split(':')[5].split('/')[1])
    
    for region, tgw_list in tgws_by_region.items():
        ec2 = boto3.client('ec2', region_name=region)
        paginator = ec2.get_paginator('describe_transit_gateway_attachments')
        resp = paginator.paginate(Filters=[{'Name': 'transit-gateway-id', 'Values': tgw_list}])
        for page in resp:
            for attachment in page['TransitGatewayAttachments']:
                if all(k in attachment for k in ['State', 'TransitGatewayId', 'TransitGatewayAttachmentId', 'ResourceType']):
                    if attachment['State'] == 'available' and attachment['ResourceType'] != 'peering':
                        if region not in ret['tgw']:
                            ret['tgw'][region] = {}
                        if attachment['TransitGatewayId'] not in ret['tgw'][region]:
                            ret['tgw'][region][attachment['TransitGatewayId']] = {}
                        ret['tgw'][region][attachment['TransitGatewayId']][attachment['TransitGatewayAttachmentId']] = {'type': attachment['ResourceType']}

    # Now find CloudWAN attachments. Find the core networks that are in this global network, then all attachments.
    global_network_id = os.environ['GLOBAL_NETWORK_ARN'].split('/')[1]
    for core_network in nm.list_core_networks()['CoreNetworks']:
        if 'GlobalNetworkId' in core_network and 'CoreNetworkId' in core_network:
            if core_network['GlobalNetworkId'] == global_network_id:
                paginator = nm.get_paginator('list_attachments')
                resp = paginator.paginate(CoreNetworkId=core_network['CoreNetworkId'])
                for page in resp:
                    for attachment in page['Attachments']:
                        if all(k in attachment for k in ['State', 'EdgeLocation', 'AttachmentType']):
                            if attachment['State'] == 'AVAILABLE':
                                if attachment['EdgeLocation'] not in ret['cwan']:
                                    ret['cwan'][attachment['EdgeLocation']] = {}
                                if core_network['CoreNetworkId'] not in ret['cwan'][attachment['EdgeLocation']]:
                                    ret['cwan'][attachment['EdgeLocation']][core_network['CoreNetworkId']] = {}
                                ret['cwan'][attachment['EdgeLocation']][core_network['CoreNetworkId']][attachment['AttachmentId']] = {'type': attachment['AttachmentType']}

    return ret


def find_alarms(ad:AttachmentData) -> AttachmentData:
    """
    Augment the given AttachmentData with a third field in AttachmentInfo named 'alarms', type dict, keys the individual fields then a dict with key 'present':boolean 
    if the alarm was found, 'name':str for the alarm name, 'region':str for the CloudWatch region the alarm is in, and key 'settings':dict for the current settings for that alarm.
    Any alarms found that are invalid (due to being incomplete for some reason or pointing to an attachment that no longer exists) are removed from CloudWatch.

    :param AttachmentData ad: AttachmentData from find_attachments
    :param List[str] fields: List of Cloudwatch metric fields to look for (i.e. BytesIn, BytesOut)
    
    :return AttachmentData: Input AD, augmented as described.
    """
    # Set up alarms structure, and remember where CloudWAN attachments are at region-wise since they always are in cloudwatch_cloudwatch_region for reporting.
    metric_names = os.environ['METRIC_NAMES'].split(',')
    cwan_regions:dict[str,str] = {}
    for type, type_data in ad.items():
        for region, region_data in type_data.items():
            for _, attachments in region_data.items():
                for attachment_id, attachment_data in attachments.items():
                    attachment_data['alarms'] = {x: {'present': False, 'name': None, 'region': None, 'settings': {}} for x in metric_names}
                    if type == 'cwan':
                        cwan_regions[attachment_id] = region

    region_list = set(ad['cwan'].keys()).union(set(ad['tgw'].keys()))
    # Ensure we have the CloudWAN region as well.
    region_list.add(get_cloudwan_cloudwatch_region())
    
    for region in region_list:
        cw = boto3.client('cloudwatch', region_name=region)
        paginator = cw.get_paginator('describe_alarms')    
        lambda_arn = get_alarm_lambda_arn(region, create_missing=False)
        if lambda_arn is None:    
            print(f"Looking for alarms in region {region}, but the lambda is not deployed there, so assuming no alarms are there.")
        else:
            # We assume if the alarm is using our Lambda as an action, it's one of our alarms.
            resp = paginator.paginate(AlarmTypes=['MetricAlarm'], ActionPrefix=lambda_arn)
            for page in resp:
                for alarm in page['MetricAlarms']:
                    net_id = None
                    attachment_id = None
                    metric_name = None
                    type = None
                    set_region = region
                    settings = {'MINUTES': int(alarm['DatapointsToAlarm'])}
                    if 'Metrics' in alarm:
                        for metric in alarm['Metrics']:
                            # We have three metrics of interest - the MetricStat with the metric we're watchng, then two math expressions with 
                            # the ANOMALY_DETECTION_BAND and the IF condition, we want to get the current values out of.
                            # ANOMALY_DETECTION_BAND(m1, 5) or IF(m1>10000000 AND m1>MAX(e1),1,0)
                            if 'Expression' in metric:
                                ab = re.search(r'ANOMALY_DETECTION_BAND\(.*,([ 0-9]+)\)', metric['Expression'])
                                if ab is not None:
                                    settings['STDDEV'] = int(ab.group(1))
                                else:
                                    ie = re.search(r'IF\(.*>([0-9]+) AND .*\)', metric['Expression'])
                                    if ie is not None:
                                        settings['MINIMUM_VALUE'] = int(ie.group(1))
                            if 'MetricStat' in metric and 'Dimensions' in metric['MetricStat']['Metric'] and 'MetricName' in metric['MetricStat']['Metric']:
                                metric_name = metric['MetricStat']['Metric']['MetricName']
                                for dim in metric['MetricStat']['Metric']['Dimensions']:
                                    if dim['Name'] == 'TransitGateway':
                                        type = 'tgw'
                                        net_id = dim['Value']
                                    elif dim['Name'] == 'TransitGatewayAttachment':
                                        attachment_id = dim['Value']
                                    elif dim['Name'] == 'CoreNetwork':
                                        type = 'cwan'
                                        net_id = dim['Value']
                                    elif dim['Name'] == 'Attachment':
                                        attachment_id = dim['Value']
                                        set_region = cwan_regions[attachment_id]
                    if type is None or net_id is None or attachment_id is None or metric_name is None or metric_name not in metric_names:
                        print(f"Found an alarm {alarm['AlarmName']} from this script, but it does not have the correct metrics set on it (type={type}, net_id={net_id}, attach_id={attachment_id}, metric_name={metric_name}). Removing it.")
                        remove_alarm(region, alarm['AlarmName'])
                    elif type not in ad or set_region not in ad[type] or net_id not in ad[type][set_region] or attachment_id not in ad[type][set_region][net_id]:
                        print(f"Found an alarm {alarm['AlarmName']} from this script, but the attachment it points to is gone (type={type}, net_id={net_id}, attach_id={attachment_id}, metric_name={metric_name}). Removing it.")
                        remove_alarm(region, alarm['AlarmName'])
                    else:     
                        ad[type][set_region][net_id][attachment_id]['alarms'][metric_name] = {'present': True, 'region': region, 'settings': settings, 'name': alarm['AlarmName']}               

    return ad


def set_alarm(type:str, region:str, net_id:str, attachment_id:str, metric_name:str) -> None:
    """
    Create our standard alarm in Cloudwatch.

    :param str type: cwan or tgw
    :param str region: Region name of the resource
    :param str net_id: net_id
    :param str attachment_id: attachment_id
    :param str metric_name: Name of the metric to set the alarm on
    """

    # If this is a CloudWAN attachment, we use cloudwan_cloudwatch_region, else we use region. Set the correct dimensions for our metric here as well.
    if type == 'tgw':
        cw = boto3.client('cloudwatch', region_name=region)
        lambda_arn = get_alarm_lambda_arn(region)
        metric_stat = {'Metric': {'Namespace': 'AWS/TransitGateway', 'MetricName': metric_name, 
                                  'Dimensions': [{'Name': 'TransitGateway', 'Value': net_id}, {'Name': 'TransitGatewayAttachment', 'Value': attachment_id}]},
                                  'Period': 60, 'Stat': 'Average'}
    else:
        cloudwan_cloudwatch_region = get_cloudwan_cloudwatch_region()
        cw = boto3.client('cloudwatch', region_name=cloudwan_cloudwatch_region)
        lambda_arn = get_alarm_lambda_arn(cloudwan_cloudwatch_region)
        metric_stat = {'Metric': {'Namespace': 'AWS/Network Manager', 'MetricName': metric_name,
                                  'Dimensions': [{'Name': 'CoreNetwork', 'Value': net_id}, {'Name': 'Attachment', 'Value': attachment_id}]},
                                  'Period': 60, 'Stat': 'Average'}

    # This format is made such that humans can understand the alarm easily in console view, although it makes
    # the scripting a bit harder by not having a consistent prefix.
    alarm_name = f'{metric_name}-{type}-{attachment_id}-{os.environ['OBJECTS_NAME']}-Alarm'

    # Create the actual alarm. The metric is in m1, the anomaly band processing is in e1. e2 creates logic that ANDs together the anomaly band being exceeded,
    # and m1 being greater than our minimum_value, and outputs a 1 or 0, and is the value Cloudwatch is looking at. Thus, we set the alarming operator to 
    # greater than 0.
    cw.put_metric_alarm(AlarmName=alarm_name,
                        AlarmDescription=f'Automatically generated alarm by {os.environ['STACK_ARN']}',
                        OKActions=[lambda_arn], AlarmActions=[lambda_arn],
                        Metrics=[{'Id': 'm1', 'MetricStat': metric_stat, 'ReturnData': False},
                                {'Id': 'e1', 'Expression': f'ANOMALY_DETECTION_BAND(m1, {os.environ['STDDEV']})', 'Label': 'Anomaly Band', 'ReturnData': False},
                                {'Id': 'e2', 'Expression': f'IF(m1>{os.environ['MINIMUM_VALUE']} AND m1>MAX(e1),1,0)', 'Label': 'Alarm Trigger', 'ReturnData': True}],
                        Threshold=0, ComparisonOperator='GreaterThanThreshold', EvaluationPeriods=int(os.environ['MINUTES']), DatapointsToAlarm=int(os.environ['MINUTES']))


def delete_alarm(type:str, region:str, attachment_id:str, metric_name:str) -> None:
    """
    Delete a standard alarm in Cloudwatch.

    :param str type: cwan or tgw
    :param str region: Region name of the resource
    :param str attachment_id: attachment_id
    :param str metric_name: Name of the metric to delete the alarm from
    """
    if type == 'tgw':
        cw = boto3.client('cloudwatch', region_name=region)
    else:
        cloudwan_cloudwatch_region = get_cloudwan_cloudwatch_region()
        cw = boto3.client('cloudwatch', region_name=cloudwan_cloudwatch_region)    

    alarm_name = f'{metric_name}-{type}-{attachment_id}-{os.environ['OBJECTS_NAME']}-Alarm'
    # Make sure to set the alarm state to OK (which will trigger the OKAction if necessary) before deleting the alarm
    cw.set_alarm_state(AlarmName=alarm_name, StateValue='OK', StateReason="Alarm is being removed.")
    cw.delete_alarms(AlarmNames=[alarm_name])


def get_partition_for_region(region_name:str) -> str:
    """
    A quick function to get the partition name for any given region.

    :param str region_name: Region name to get.
    :return str: The partition name ('aws', etc.)
    """
    session = boto3.Session()
    return session.get_partition_for_region(region_name)


def get_cloudwan_cloudwatch_region() -> str:
    """
    As per https://docs.aws.amazon.com/network-manager/latest/cloudwan/cloudwan-cloudwatch-metrics.html, CloudWAN metrics are only
    available in one region per partition. This returns those values. 

    :param str region_name: Region name to find
    :return str: Region name CloudWAN's CloudWatch metrics are in
    """
    match os.environ['GLOBAL_NETWORK_ARN'].split(':')[1]:
        case 'aws':
            return 'us-west-2'
        case 'aws-us-gov':
            return 'us-gov-west-1'
        case _:
            # Could only get here if a partition has been added and this code isn't updated - raise an exception
            raise Exception(f'Unhandled partition {os.environ['GLOBAL_NETWORK_ARN'].split(':')[1]}. The get_cloudwan_cloudwatch_region function needs updating against the AWS documentation.')


def get_alarm_names(region_name:str) -> dict[str, str]:
    """
    Calculate the lambda and S3 names for the alarm function to use for a given region. Returns some additional bits that are
    needed anyway for the calculation

    :param str region_name: Region name to get names for
    :return dict[str, str]: Keys of 
                            'bucket_name' and 'bucket_arn' for the S3 bucket, 
                            'lambda_name' for the lambda name,
                            'partition' for the partition of the region
    """
    gn_uuid = os.environ['GLOBAL_NETWORK_ARN'].split('-')[3]
    ret:dict[str,str] = {}
    ret['partition'] = get_partition_for_region(region_name)
    ret['bucket_name'] = f'{os.environ['OBJECTS_NAME']}-{region_name}-{gn_uuid}'
    ret['bucket_arn'] = f'arn:{ret['partition']}:s3:::{ret['bucket_name']}'
    ret['lambda_name'] = f'{os.environ['OBJECTS_NAME']}_Alarm_Handler'
    return ret


def get_alarm_lambda_arn(region_name:str, create_missing:bool = True) -> Optional[str]:
    """
    Return the lambda ARN of our alarm lambda for the given region. Creates the lambda, if it's not already present.

    :param str region_name: Region name for the lambda
    :param bool create_missing: Create the lambda, if it's not present in the region yet.
    :return str: A full ARN (that may have just been created)
    """

    names = get_alarm_names(region_name)
    l = boto3.client('lambda', region_name=region_name)

    # See if the function already exists.  If it does, just return its ARN.
    try:
        resp = l.get_function(FunctionName=names['lambda_name'])
        return resp['Configuration']['FunctionArn']
    except botocore.exceptions.ClientError as e:
        # This is likely ResourceNotFoundException because the function isn't here yet, but let's be sure.
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            raise e
    
    # Build out the new region - this function returns the ARN we need.
    if create_missing:
        return new_region_build(dest_region_name=region_name)
    else:
        return None


def get_alarm_handler_lambda_code() -> bytes:
    """
    Return the data needed for a ZipFile input of a create_function lambda call, based on a copy of the AlarmLambda function in the local region.
    """
    names = get_alarm_names(region_name=os.environ['AWS_REGION'])
    l = boto3.client('lambda')
    lambda_data = l.get_function(FunctionName=names['lambda_name'])
    req = urllib.request.urlopen(urllib.request.Request(url=lambda_data['Code']['Location'], method='GET'), timeout=5)
    return req.read()


def new_region_build(dest_region_name:str) -> str:
    """
    Set up a new region for use. This involves creating an S3 bucket and copying the policy from source region, then copying the lambda
    function from the source region.

    :param str source_region_name: The region to copy from.
    :param str dest_region_name: The region to copy to.

    :return str: The ARN of the lambda function in the new region.
    """
    source_names = get_alarm_names(os.environ['AWS_REGION'])
    dest_names = get_alarm_names(dest_region_name)

    # The lambda requires a regional S3 bucket - create one. Wrapped in a try block because there's a chance this bucket already exists
    # (this code is running multiple times for some reason).
    dest_s3 = boto3.client('s3', region_name=dest_region_name)
    try:
        # Don't ask - I don't know why either.
        if dest_region_name != 'us-east-1':
            resp = dest_s3.create_bucket(Bucket=dest_names['bucket_name'], CreateBucketConfiguration={'LocationConstraint': dest_region_name})
        else:
            resp = dest_s3.create_bucket(Bucket=dest_names['bucket_name'])
        print(f'Expanding to a new region: Created a new bucket {dest_names['bucket_name']} in region {dest_region_name} for logs.')

    except botocore.exceptions.ClientError as e:
        # If we already have and own the bucket, ignore and move on, otherwise raise exception.
        if e.response['Error']['Code'] != 'BucketAlreadyOwnedByYou':
            raise e        

    # Copy the bucket policy from source to dest, replacing region names.
    src_s3 = boto3.client('s3')
    src_policy = src_s3.get_bucket_policy(Bucket=source_names['bucket_name'])
    
    # Replace the region names in the policy. Replace region name in arn (this catches things like 'arn:aws:logs::us-west-2', etc)
    dst_policy = re.sub(fr'(arn:[a-z-]+:[a-z0-9-]*:){os.environ['AWS_REGION']}:', fr'\1:{dest_region_name}:', src_policy['Policy'])
    # Replace bucket ARNs:
    dst_policy = dst_policy.replace(source_names['bucket_arn'], dest_names['bucket_arn'])
    # Apply to destination.
    dest_s3.put_bucket_policy(Bucket=dest_names['bucket_name'], Policy=dst_policy)
    print(f'Copied bucket policy from {source_names['bucket_name']} to {dest_names['bucket_name']}')

    # Copy bucket lifecycle configuration
    try:
        resp = src_s3.get_bucket_lifecycle_configuration(Bucket=source_names['bucket_name'])    
        dest_s3.put_bucket_lifecycle_configuration(Bucket=dest_names['bucket_name'], LifecycleConfiguration={'Rules': resp['Rules']})
        print(f'Copied bucket lifecycle configuration from {source_names['bucket_name']} to {dest_names['bucket_name']}')
    except botocore.exceptions.ClientError as e:
        # Someone maybe deleted the lifecycle configuration we made on the original bucket? If so, just ignore it and move on.
        if e.response['Error']['Code'] != 'NoSuchLifecycleConfiguration':
            raise e

    # Create the new lambda.
    l = boto3.client('lambda', region_name=dest_region_name)    
    try:
        resp = l.create_function(FunctionName=dest_names['lambda_name'], Runtime='python3.12', Role=os.environ['ALARM_LAMBDA_ROLE'], Handler='handler',
                                Code={'ZipFile': get_alarm_handler_lambda_code()}, Timeout=5, 
                                Environment={'Variables': {'SNS_TOPIC': os.environ['SNS_TOPIC'], 'S3_BUCKET': dest_names['bucket_arn']}})
        print(f'Expanding to a new region: Created a new lambda {dest_names['lambda_name']} in region {dest_region_name}')
        return resp['FunctionArn']
    except botocore.exceptions.ClientError as e:
        # It's remotely possible a different lambda run beat us to this part - if so just get the (new) ARN.
        if e.response['Error']['Code'] != 'ResourceConflictException':    
            raise e
        else:
            # Retry the fetch. 
            resp = l.get_function(FunctionName=dest_names['lambda_name'])
            return resp['Configuration']['FunctionArn']


def remove_alarm(region_name: str, alarm_name: str) -> None:
    """
    Deletes an alarm we created.
    :param str region_name: Region of the CloudWatch instance with the alarm
    :param str alarm_name: Alarm name
    """
    cw = boto3.client('cloudwatch', region_name=region_name)
    # Make sure to set the alarm state to OK (which will trigger the OKAction if necessary) before deleting the alarm
    cw.set_alarm_state(AlarmName=alarm_name, StateValue='OK', StateReason="Alarm is being removed.")
    cw.delete_alarms(AlarmNames=[alarm_name])


def do_resync():
    """
    Resync the state between alarms created in CloudWatch, and the attachments actually present. Handles new attachments and attachments that have been deleted.
    Also handles if environment parameters for the alarms (THRESHOLD, MINIMUM_VALUE, MINUTES) have been changed and updates the alarms to match.
    """
    # Gather our current state. This also removes any bad alarms.
    ad = find_alarms(find_attachments())

    # What the alarm settings should be
    settings = {'MINIMUM_VALUE': int(os.environ['MINIMUM_VALUE']), 'STDDEV': int(os.environ['STDDEV']), 'MINUTES': int(os.environ['MINUTES'])}

    # Set all alarms that need to be set.
    for type, type_data in ad.items():
        for region, region_data in type_data.items():
            for net_id, attachments in region_data.items():
                for attachment_id, attach_data in attachments.items():
                    for metric_name in os.environ['METRIC_NAMES'].split(','):
                        if attach_data['alarms'][metric_name]['present'] is False:
                            print(f"Missing alarm for {region} attachment {attachment_id} metric {metric_name} - creating it.")
                            set_alarm(type, region, net_id, attachment_id, metric_name)
                        elif attach_data['alarms'][metric_name]['settings'] != settings:
                            print(f"Settings have changed for alarm {attach_data['alarms'][metric_name]['name']} - current settings are {attach_data['alarms'][metric_name]['settings']}, new settings are {settings}. Rebuilding the alarm.")
                            remove_alarm(attach_data['alarms'][metric_name]['region'], attach_data['alarms'][metric_name]['name'])
                            set_alarm(type, region, net_id, attachment_id, metric_name)


def do_purge():
    """
    Purge everything we've created as part of this.
    """
    # Delete all alarms.
    regions:set[str] = set()
    metric_names = os.environ['METRIC_NAMES'].split(',')
    ad = find_alarms(find_attachments())
    for type, type_data in ad.items():
        for region, region_data in type_data.items():
            regions.add(region)
            for net_id, attachments in region_data.items():
                for attachment_id, _ in attachments.items():
                    for metric_name in metric_names:
                        if ad[type][region][net_id][attachment_id]['alarms'][metric_name] is True:
                            alarm_name = f'{metric_name}-{type}-{attachment_id}-{os.environ['OBJECTS_NAME']}-Alarm'
                            remove_alarm(region, alarm_name)

    # Delete the lambdas and buckets from all regions except ours (CloudFormation will handle that). 
    # We wrap this in try blocks as in case of aborted deployments or running at the same time, we could have already deleted these.
    regions.discard(os.environ['AWS_REGION'])
    for region_name in regions:
        # Lambda first.
        names = get_alarm_names(region_name)
        l = boto3.client('lambda', region_name=region_name)
        try:
            l.delete_function(FunctionName=names['lambda_name'])
            print(f"Purge: Region {region_name}: Removed lambda {names['lambda_name']}")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                raise e

        # S3 bucket and its contents next.
        s3 = boto3.resource('s3')
        try:
            bucket = s3.Bucket(names['bucket_name'])
            bucket.objects.all().delete()
            bucket.delete()
            print(f"Purge: Region {region_name}: Removed S3 bucket {names['bucket_name']}")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucket':
                raise e


def process_nm(event, context):
    """
    Process a notification from Network Manager. This event can be a few different types, and can be in any region, so this function needs to handle all
    of that.
    """
    # These events get raised similarly for TGW and CloudWAN, but with different elements in the detail section. See
    # https://docs.aws.amazon.com/network-manager/latest/tgwnm/monitoring-events.html for help decoding this section.
    match event['detail']['changeType']:
        case 'VPN-CONNECTION-CREATED' | 'VPC-ATTACHMENT-CREATED' | 'DXGW-ATTACHMENT-CREATED' | 'CONNECT_ATTACHMENT_CREATED':
            # CloudWAN will have edgeLocation, Transit Gateway has region.
            if 'edgeLocation' in event['detail']:
                for metric in os.environ['METRIC_NAMES']:
                    set_alarm(type='cwan', region=event['detail']['edgeLocation'], metric_name=metric,
                              net_id=[s for s in event['resources'] if 'core-network' in s][0].split('/')[1],
                              attachment_id=event['detail']['attachmentArn'].split('/')[1])
            else:
                for metric in os.environ['METRIC_NAMES']:
                    set_alarm(type='tgw', region=event['detail']['region'], metric_name=metric,
                              net_id=event['detail']['transit-gateway-arn'].split('/')[1],
                              attachment_id=event['detail']['transit-gateway-attachment-arn'].split('/')[1])            
        case 'VPN-CONNECTION-DELETED' | 'VPC-ATTACHMENT-DELETED' | 'DXGW-ATTACHMENT-DELETED' | 'CONNECT_ATTACHMENT_DELETED':
            # CloudWAN will have edgeLocation, Transit Gateway has region.
            if 'edgeLocation' in event['detail']:
                for metric in os.environ['METRIC_NAMES']:
                    delete_alarm(type='cwan', region=event['detail']['edgeLocation'], metric_name=metric,
                                 attachment_id=event['detail']['attachmentArn'].split('/')[1])
            else:
                for metric in os.environ['METRIC_NAMES']:
                    delete_alarm(type='tgw', region=event['detail']['region'], metric_name=metric,
                                 attachment_id=event['detail']['transit-gateway-attachment-arn'].split('/')[1])
        case 'TGW-DELETED' | 'TGW-CREATED':
            # Rethink the world.
            do_resync()
        case _:
            # Ignore the other types (things like peering connections, etc)
            pass


def process_timer(event, context):
    # The timer fires off every so often (configurable) just to make sure some events didn't get missed. 
    # Do a resync to accomplish this.
    do_resync()


def process_cloudformation(event, context):
    # If a CREATE, we need to do a resync which will catch every attachment that may have been missed.
    # If an UPDATE, we do a resync as well, which will correct any changes to settings of the alarms.
    # If a DELETE, delete all alarms that were created by this.
    if event['RequestType'] == 'Create':
        do_resync()
    elif event['RequestType'] == 'Delete':
        do_purge()
    elif event['RequestType'] == 'Update':
        do_resync()
    cfnresponse.send(event, context, cfnresponse.SUCCESS, {"Data": "Successful"})


def handler(event: Dict[str, Any], context):
    timer = threading.Timer((context.get_remaining_time_in_millis() / 1000.00) - 0.5, timeout, args=[event, context])
    timer.start()

    try:
        # Are we being called with a EventManager notification from Network Manager
        if 'source' in event and event['source'] == 'aws.networkmanager':
            print(f"Processing Network Manager event, event data: {event}")
            process_nm(event, context)
        # Are we being called by EventManager from our timer?
        elif 'source' in event and event['source'] == 'aws.events':
            print(f"Processing Event Bridge timer event, event data: {event}")
            process_timer(event, context)
        # Are we being called from CloudFormation as part of initial install, update, or delete?
        elif 'StackId' in event:
            print(f"Processing CloudFormation event, event data: {event}")
            process_cloudformation(event, context)
        else:
            # Likely testing but didn't give correct parameters.
            print(f"Lambda function called but event does not contain EventManager or CloudFormation data. Aborting.")
        return

    except Exception as e:
        logging.error('Exception: %s' % e, exc_info=True)
        logging.error(f"Data from request:\nevent={event}\ncontext={context}")

        if 'ResponseURL' in event:
            cfnresponse.send(event, context, cfnresponse.FAILED, {"e": f'{e}'}, reason=f'{e}')

        # Do a best effort notification of the exception
        sns = boto3.client('sns')
        sns.publish(TopicArn=os.environ['SNS_TOPIC'], Subject=f'Lambda {os.environ['AWS_LAMBDA_FUNCTION_NAME']} in {os.environ['AWS_REGION']} had an exception.',
            Message=f'The lambda function {os.environ['AWS_LAMBDA_FUNCTION_NAME']} in {os.environ['AWS_REGION']} had an exception.\n\n'
            f'Exception: {e}\n\n'
            f'Event data: {event}')
        
        raise e
    