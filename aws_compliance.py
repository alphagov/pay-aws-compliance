from __future__ import print_function
import json
import time
import sys
import re
import getopt
import os
from datetime import datetime
import boto3

IAM_CLIENT = boto3.client('iam')
S3_CLIENT  = boto3.client('s3')
REGION     = os.getenv('AWS_DEFAULT_REGION') or 'eu-west-1'

# Config
SEND_REPORT_TO_SNS = os.getenv('SEND_REPORT_TO_SNS')
SNS_TOPIC_ARN      = os.getenv('SNS_TOPIC_ARN')
ONLY_SHOW_FAILED   = os.getenv('ONLY_SHOW_FAILED')
S3_BUCKETS_TO_SKIP = os.getenv('S3_BUCKETS_TO_SKIP')

# S3 versioning enabled on all buckets
def s3_versioning_enabled():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "s3_versioning_enabled"
    description = "Ensure S3 versioning is enabled on all buckets"
    scored = False
    for bucket in S3_CLIENT.list_buckets()['Buckets']:
        if should_skip_bucket(bucket):
            continue
        try:
            versioning = S3_CLIENT.get_bucket_versioning(Bucket=bucket['Name'])
        except:
            result = False
            failReason = "Buckets found without versioning enabled"
            offenders.append(bucket['Name']) 
        try:
            versioning_status = versioning['Status']
            if (versioning_status == 'Enabled'):
                pass
        except:
            result = False
            failReason = "Buckets found without versioning enabled"
            offenders.append(bucket['Name']) 

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# S3 logging enabled on all buckets
def s3_logging_enabled():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "s3_logging_enabled"
    description = "Ensure S3 logging is enabled on all buckets"
    scored = False
    for bucket in S3_CLIENT.list_buckets()['Buckets']:
        if should_skip_bucket(bucket):
            continue
        try:
            logging = S3_CLIENT.get_bucket_logging(Bucket=bucket['Name'])
        except:
            result = False
            failReason = "Buckets found without logging enabled"
            offenders.append(bucket['Name']) 
        try:
            if logging['LoggingEnabled']:
                pass
        except:
            result = False
            failReason = "Buckets found without logging enabled"
            offenders.append(bucket['Name']) 

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


def should_skip_bucket(bucket):
    if S3_BUCKETS_TO_SKIP:
        if bucket['Name'] in S3_BUCKETS_TO_SKIP.split(','):
            return True


def get_account_alias():
    """AWS Account Alias
    Returns:
        TYPE: String
    """
    try:
        account_alias = IAM_CLIENT.list_account_aliases()['AccountAliases'][0]
    except:
        account_alias = 'could not fetch account alias'
    return account_alias


def set_evaluation(invokeEvent, mainEvent, annotation):
    """Summary

    Args:
        event (TYPE): Description
        annotation (TYPE): Description

    Returns:
        TYPE: Description
    """
    configClient = boto3.client('config')
    if len(annotation) > 0:
        configClient.put_evaluations(
            Evaluations=[
                {
                    'ComplianceResourceType': 'AWS::::Account',
                    'ComplianceResourceId': mainEvent['accountId'],
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': str(annotation),
                    'OrderingTimestamp': invokeEvent['notificationCreationTime']
                },
            ],
            ResultToken=mainEvent['resultToken']
        )
    else:
        configClient.put_evaluations(
            Evaluations=[
                {
                    'ComplianceResourceType': 'AWS::::Account',
                    'ComplianceResourceId': mainEvent['accountId'],
                    'ComplianceType': 'COMPLIANT',
                    'OrderingTimestamp': invokeEvent['notificationCreationTime']
                },
            ],
            ResultToken=mainEvent['resultToken']
        )


def json_output(controlResult):
    """Summary

    Args:
        controlResult (TYPE): Description

    Returns:
        TYPE: Description
    """
    print(json.dumps(controlResult, sort_keys=False, indent=4, separators=(',', ': ')))


def shortAnnotation(controlResult):
    """Summary

    Args:
        controlResult (TYPE): Description

    Returns:
        TYPE: Description
    """
    annotation = []
    longAnnotation = False
    for m, _ in enumerate(controlResult):
        for n in range(len(controlResult[m])):
            if controlResult[m][n]['Result'] is False:
                if len(str(annotation)) < 220:
                    annotation.append(controlResult[m][n]['ControlId'])
                else:
                    longAnnotation = True
    if longAnnotation:
        annotation.append("etc")
        return "{\"Failed\":" + json.dumps(annotation) + "}"
    else:
        return "{\"Failed\":" + json.dumps(annotation) + "}"


def send_results_to_sns(controls, account):
    """Summary

    Args:
        controls (TYPE): Controls object

    Returns:
        TYPE: Description
    """
    # Get correct region for the TopicARN
    region = (SNS_TOPIC_ARN.split("sns:", 1)[1]).split(":", 1)[0]
    client = boto3.client('sns', region_name=region)
    subject = "AWS Compliance Report - " + account + " - " + str(time.strftime("%c"))
    body = json.dumps(controls, sort_keys=False, indent=4, separators=(',', ': '))
    response = client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=body
    )
    print("SNS Response: " + str(response))


def lambda_handler(event, context):
    """Summary

    Args:
        event (TYPE): Description
        context (TYPE): Description

    Returns:
        TYPE: Description
    """
    try:
        if event['configRuleId']:
            configRule = True
            # Verify correct format of event
            invokingEvent = json.loads(event['invokingEvent'])
    except:
        configRule = False

    account_alias = get_account_alias()

    controls = []
    controls.append(s3_versioning_enabled())
    controls.append(s3_logging_enabled())

    if ONLY_SHOW_FAILED == 'true':
        controls = list(filter(lambda x: x['Result'] == False, controls))

    if SEND_REPORT_TO_SNS == 'true':
        if bool(controls):
            send_results_to_sns(controls, account_alias)

    if not bool(controls):
        controls = 'OK - AWS Compliance report pass'

    json_output(controls)
    
    # Report back to Config if we detected that the script is initiated from Config Rules
    if configRule:
        evalAnnotation = shortAnnotation(controls)
        set_evaluation(invokingEvent, event, evalAnnotation)


if __name__ == '__main__':
    boto3.setup_default_session(region_name=REGION)
    lambda_handler("test", "test")
