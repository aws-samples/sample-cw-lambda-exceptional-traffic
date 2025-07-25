"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

alarm_handler.py

Python lambda script to handle CloudWatch alarms being set and cleared, triggering captures on the affected
Transit Gateway attachment.

This script relies on environment variables to pass in how things work. Those variables are:

S3_BUCKET - The full ARN of the bucket and path to save flow logs into
SNS_TOPIC - The SNS topic ARN to send notifications to

Additionally, it leverages some variables set by AWS Lambda itself - AWS_LAMBDA_FUNCTION_NAME and AWS_REGION.

API references:
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/create_flow_logs.html
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_flow_logs.html
"""
import boto3
import logging
import os
import datetime

# Change this to be whatever fields you like. The default, provided here, are all fields.
# See https://docs.aws.amazon.com/vpc/latest/tgw/tgw-flow-logs.html#flow-log-records for information.
TGW_FLOW_LOG_FORMAT = '${version} ${resource-type} ${account-id} ${tgw-id} ${tgw-attachment-id} ${tgw-src-vpc-account-id} ${tgw-dst-vpc-account-id} ${tgw-src-vpc-id} ${tgw-dst-vpc-id} ${tgw-src-subnet-id} ${tgw-dst-subnet-id} ${tgw-src-eni} ${tgw-dst-eni} ${tgw-src-az-id} ${tgw-dst-az-id} ${tgw-pair-attachment-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${log-status} ${type} ${packets-lost-no-route} ${packets-lost-blackhole} ${packets-lost-mtu-exceeded} ${packets-lost-ttl-expired} ${tcp-flags} ${region} ${flow-direction} ${pkt-src-aws-service} ${pkt-dst-aws-service}'
CREATOR_TAG = f"Lambda {os.environ['AWS_LAMBDA_FUNCTION_NAME']} in {os.environ['AWS_REGION']}"

def get_flow_log_status(ec2: object, resource_id: str) -> bool:
    """
    Determine current flow log status

    :param ec2: Boto3 EC2 Client
    :param resource_id: As per create_flow_log ResourceId

    :return: Return True if a flow log is already active for this object, False otherwise.
    """
    fls = ec2.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
    for fl in fls['FlowLogs']:
        if fl['ResourceId'] == resource_id:
            if fl['FlowLogStatus'] == 'ACTIVE' and 'Tags' in fl:
                    for tag in fl['Tags']:
                        if tag['Key'] == 'Creator' and tag['Value'] == CREATOR_TAG:
                            return True
    return False


def format_bytes(bytes_value: float) -> str:
    """
    Format bytes into human readable format.
    :param bytes_value: Number of bytes
    :return: Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def convert_to_metric(d: dict) -> dict:
    # The AlarmData has the metric info, but:
    # - Every key is lowercase instead of upper like we need to GetMetricStats
    # - It's Name instead of MetricName
    # - The Dimensions are in a different format.
    # Correct this.
    ret = {}
    for k, v in d.items():
        newk = k[0].upper() + k[1:]
        if newk == 'Name':
            newk = 'MetricName'
        if isinstance(v, dict):
            if newk == 'Dimensions':
                ret[newk] = [{'Name': k, 'Value': v} for k, v in convert_to_metric(v).items()]
            else:
                ret[newk] = convert_to_metric(v)
        else:
            if newk == 'ReturnData':
                ret[newk] = True
            else:
                ret[newk] = v

    return ret


def get_alarming_metric_str(alarm_data: dict) -> str:
    # We have a composite alarm - while the alarm we create is named something like BytesOut-tgw-tgw-attach-0ab9d8b7bcab228d4-alarms-Alarm,
    # that by itself doesn't help - it's two 1 or 0 evaluations. We have to get the alarm configuration and get the 'm1' metric to get the
    # actual values. Start with getting the metric.
    cw = boto3.client('cloudwatch')
    alarming_metric = None

    # Get metric dimensions
    for m in alarm_data['configuration']['metrics']:
        if 'metricStat' in m:
            alarming_metric = convert_to_metric(m)
            break
    if alarming_metric is None:
        print(f'Unable to find the metric for alarm_data {alarm_data}')
        return ''

    # Get most recent data point and detection band for that metric
    endtime = datetime.datetime.now(datetime.timezone.utc)
    starttime = endtime - datetime.timedelta(minutes=15)
    mdq = [alarming_metric, {"Id": "ab1", "Expression": "ANOMALY_DETECTION_BAND(m1)"}]
    metric_data = cw.get_metric_data(MetricDataQueries=mdq, EndTime=endtime, StartTime=starttime, MaxDatapoints=1, ScanBy='TimestampDescending')
    if len(metric_data['MetricDataResults']) == 0 or len(metric_data['MetricDataResults'][0]['Values']) == 0:
        print(f'Unable to get metric data for alarm_data {alarm_data}')
        return ''

    # Get current value and the high water AD band. Convert units for a couple common metrics.
    cur_value = None
    high_band = None
    for md in metric_data['MetricDataResults']:
        if md['Id'] == 'm1':
            cur_value = md['Values'][0]
        elif md['Id'] == 'ab1' and md['Label'][-4:] == 'High':
            high_band = md['Values'][0]

    if alarming_metric['MetricStat']['Metric']['MetricName'] in ('BytesIn', 'BytesOut'):
        cur_value = format_bytes(cur_value)
        high_band = format_bytes(high_band)

    # We have everything now - return string
    return f"Alarm Information:\nAlarm: {alarm_data['alarmName']}\nCurrent value: {cur_value} per minute\nAnomaly detection high band: {high_band} per minute.\n\n"


def disable_flow_log(ec2: object, sns: object, resource_type: str, resource_id: str, s3_dest_arn: str, logging_sns: str, alarm_data: dict):
    """
    Disable a flow log for the given resource.
    :param ec2: Boto3 EC2 Client
    :param sns: Boto3 SNS Client
    :param resource_type: As per create_flow_log ResourceType
    :param resource_id: As per create_flow_log ResourceId
    :param s3_dest_arn: S3 destination ARN, ala arn:aws:s3:::bucket/subfolder/
    :param logging_sns: SNS topic to send state changes to.
    """
    fls = ec2.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': [resource_id]}])
    start_time = None
    for fl in fls['FlowLogs']:
        if fl['ResourceId'] == resource_id and fl['FlowLogStatus'] == 'ACTIVE' and 'Tags' in fl:
            for tag in fl['Tags']:
                if tag['Key'] == 'Creator' and tag['Value'] == CREATOR_TAG:
                    ret = ec2.delete_flow_logs(FlowLogIds=[fl['FlowLogId']])
                    if len(ret['Unsuccessful']):
                        raise Exception(f"Unable to delete flow log for {resource_type}, {resource_id}, at {s3_dest_arn}: {ret['Unsuccessful'][0]['Error']}")
                    start_time = fl['CreationTime']
    if start_time is None:
        print(f"disable_flow_log called for a flow log that doesn't exist ({resource_type}, {resource_id}, {s3_dest_arn}). Ignoring.")
        return

    print(f'Stopped flow log for {resource_type}, {resource_id}, at {s3_dest_arn}')

    # Build the S3 path to help the person receiving the email out. The path is based on date in UTC - get that.
    utc = datetime.datetime.now(datetime.timezone.utc)
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    s3_path = f's3://{s3_dest_arn.split(':')[-1]}/AWSLogs/{account_id}/vpcflowlogs/{os.environ['AWS_REGION']}/{utc.year}/{utc.month:02}/{utc.day:02}'

    # How long did we have the flow log for?
    end_time = datetime.datetime.now(start_time.tzinfo)
    delta_time = end_time - start_time

    sns.publish(TopicArn=logging_sns, Subject=f'Disabled flow log for {resource_type}, {resource_id}',
                Message=f'Flow logging has been disabled on {resource_type} ID {resource_id} to {s3_dest_arn}. It ran for {delta_time}.\n\n'
                        f'You can view the logs collected by running aws s3 ls {s3_path}/\n\n'
                        f'{get_alarming_metric_str(alarm_data)}'
                        f'This message is from lambda function {os.environ['AWS_LAMBDA_FUNCTION_NAME']} in region {os.environ['AWS_REGION']}.')


def enable_flow_log(ec2: object, sns: object, resource_type: str, resource_id: str, s3_dest_arn: str, logging_sns: str, alarm_data: dict):
    """
    Enable a flow log for the given resource.
    :param ec2: Boto3 EC2 Client
    :param sns: Boto3 SNS Client
    :param resource_type: As per create_flow_log ResourceType
    :param resource_id: As per create_flow_log ResourceId
    :param s3_dest_arn: S3 destination ARN, ala arn:aws:s3:::bucket/subfolder/
    :param logging_sns: SNS topic to send state changes to.
    """
    client_token = f'{resource_type}-{resource_id}-enable'
    ret = ec2.create_flow_logs(ClientToken=client_token, ResourceType=resource_type, ResourceIds=[resource_id],
                               LogDestinationType='s3', LogDestination=s3_dest_arn, LogFormat=TGW_FLOW_LOG_FORMAT,
                               TagSpecifications=[{'ResourceType': 'vpc-flow-log', 'Tags': [{'Key': 'Creator', 'Value': f'Lambda {os.environ['AWS_LAMBDA_FUNCTION_NAME']} in {os.environ['AWS_REGION']}'}]}])

    if len(ret['Unsuccessful']):
        raise Exception(f"Unable to create flow log for {resource_type}, {resource_id}, at {s3_dest_arn}: {ret['Unsuccessful'][0]['Error']}")

    print(f'Started flow log for {resource_type}, {resource_id}, at {s3_dest_arn}')

    # Build the S3 path to help the person receiving the email out. The path is based on date in UTC - get that.
    utc = datetime.datetime.now(datetime.timezone.utc)
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    s3_path = f's3://{s3_dest_arn.split(':')[-1]}/AWSLogs/{account_id}/vpcflowlogs/{os.environ['AWS_REGION']}/{utc.year}/{utc.month:02}/{utc.day:02}'

    sns.publish(TopicArn=logging_sns, Subject=f'Enabled flow log for {resource_type}, {resource_id}',
                Message=f'Flow logging has been enabled on {resource_type} ID {resource_id} to {s3_dest_arn}.\n\n'
                        f'You can view the logs collected by running: aws s3 ls {s3_path}/\n\n'
                        f'{get_alarming_metric_str(alarm_data)}'
                        f'This message is from lambda function {os.environ['AWS_LAMBDA_FUNCTION_NAME']} in region {os.environ['AWS_REGION']}.')

def set_flow_log(ec2: object, sns: object, resource_type: str, resource_id: str, s3_dest_arn: str, enabled: bool, logging_sns: str, alarm_data: dict):
    """
    Ensures a flow log is set for the given resource. Adds or deletes as needed, but won't do anything if the
    state is already correct.

    :param ec2: Boto3 EC2 Client
    :param sns: Boto3 SNS Client
    :param resource_type: As per create_flow_log ResourceType
    :param resource_id: As per create_flow_log ResourceId
    :param s3_dest_arn: S3 destination ARN, ala arn:aws:s3:::bucket/subfolder/
    :param enabled: True to ensure the log is enabled, False to ensure it is disabled.
    :param logging_sns: SNS topic to send state changes to.
    :return:
    """

    # See if we have a log going currently.
    current_status = get_flow_log_status(ec2, resource_id)

    # Do we need to do a state change? If so, do it.
    if current_status and not enabled:
        disable_flow_log(ec2, sns, resource_type, resource_id, s3_dest_arn, logging_sns, alarm_data)
    elif not current_status and enabled:
        enable_flow_log(ec2, sns, resource_type, resource_id, s3_dest_arn, logging_sns, alarm_data)
    else:
        print(f'No flow log state change needed for {resource_type}, {resource_id}, at {s3_dest_arn} - current status is {current_status}, enabled is {enabled}')


def handler(event, context):
    try:
        ec2 = boto3.client('ec2')
        sns = boto3.client('sns')

        # See https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html for an example o
        # the event object that is being sent here.
        print(f"Processing alarm event. Event data {event}")

        # Make sure this is a Transit Gateway attachment.
        if event['alarmData']['configuration']['metrics'][0]['metricStat']['metric']['namespace'] == 'AWS/TransitGateway':
            tgw_attachment_id = event['alarmData']['configuration']['metrics'][0]['metricStat']['metric']['dimensions']['TransitGatewayAttachment']
            # This will be True if we're going into alarm, or False when we're coming out of it.
            set_or_reset = event['alarmData']['state']['value'] == 'ALARM'
            # Where will this go?
            s3_dest_arn = f'arn:aws:s3:::{os.environ['S3_BUCKET']}/transit_gateway_logs/{tgw_attachment_id}'
            set_flow_log(ec2, sns, 'TransitGatewayAttachment', tgw_attachment_id, s3_dest_arn, set_or_reset, os.environ['SNS_TOPIC'], event['alarmData'])
        return

    except Exception as e:
        logging.error('Exception: %s' % e, exc_info=True)
        logging.error(f"Data from request:\nevent={event}\ncontext={context}")

        # This next line could error again on us, but CFN has already been responded to, so this is a 'best-effort'
        # type call.
        sns.publish(TopicArn=os.environ['SNS_TOPIC'], Subject=f'Lambda {os.environ['AWS_LAMBDA_FUNCTION_NAME']} in {os.environ['AWS_REGION']} had an exception.',
                    Message=f'The lambda function {os.environ['AWS_LAMBDA_FUNCTION_NAME']} in {os.environ['AWS_REGION']} had an exception.\n\n'
                    f'Exception: {e}\n\n'
                    f'Event data: {event}')
        raise e
