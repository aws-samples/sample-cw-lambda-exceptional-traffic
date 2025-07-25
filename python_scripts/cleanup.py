"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0

cleanup.py

Python lambda script to clean up old alarms on delete or update of the single TGW stack
"""
import boto3
import cfnresponse
import logging
import threading
import os

def timeout(event, context):
    logging.error('Execution is about to time out, sending failure response to CloudFormation')
    cfnresponse.send(event, context, cfnresponse.FAILED, {}, None)


def handler(event, context):
    timer = threading.Timer((context.get_remaining_time_in_millis() / 1000.00) - 0.5, timeout, args=[event, context])
    timer.start()

    try:
        if event['RequestType'] == 'Delete':
            # Clean up existing alarms
            cw = boto3.client('cloudwatch')

            # Get current alarms using our lambda as an action and delete them.
            alarms_to_remove = []
            paginator = cw.get_paginator('describe_alarms')
            resp = paginator.paginate(AlarmTypes=['MetricAlarm'], ActionPrefix=os.environ['LAMBDA_REF'])
            for page in resp:
                for ca in page['MetricAlarms']:
                    alarms_to_remove.append(ca['AlarmName'])
            if len(alarms_to_remove):                        
                cw.set_alarm_state(AlarmName=alarm_name, StateValue='OK', StateReason="Alarm is being removed.")    
                cw.delete_alarms(AlarmNames=alarms_to_remove)
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {'Data': f'{len(alarms_to_remove)} alarms removed.'})
        else:
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {'Data': 'No action needed.'})
    except Exception as e:
        logging.error('Exception: %s' % e, exc_info=True)
        logging.error(f"Data from request:\nevent={event}\ncontext={context}")
        cfnresponse.send(event, context, cfnresponse.FAILED, {"e": f'{e}'})
        raise e