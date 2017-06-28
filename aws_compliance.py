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
EC2_CLIENT = boto3.client('ec2')
S3_CLIENT  = boto3.client('s3')
REGION     = os.getenv('AWS_DEFAULT_REGION') or 'eu-west-1'

# Config
SEND_REPORT_TO_SNS       = os.getenv('SEND_REPORT_TO_SNS')
SNS_TOPIC_ARN            = os.getenv('SNS_TOPIC_ARN')
ONLY_SHOW_FAILED         = os.getenv('ONLY_SHOW_FAILED')
S3_BUCKETS_TO_SKIP       = os.getenv('S3_BUCKETS_TO_SKIP')
VULS_REPORT_BUCKET       = os.getenv('VULS_REPORT_BUCKET') or 'pay-govuk-dev-vuls'
VULS_HIGH_THRESHOLD      = os.getenv('VULS_HIGH_THRESHOLD') or 7
VULS_MEDIUM_THRESHOLD    = os.getenv('VULS_MEDIUM_THRESHOLD') or 4.5
VULS_LOW_THRESHOLD       = os.getenv('VULS_LOW_THRESHOLD') or 0
VULS_UNKNOWN_THRESHOLD   = os.getenv('VULS_UNKNOWN_THRESHOLD') or -1
VULS_IGNORE_UNSCORED_CVE = os.getenv('VULS_IGNORE_UNSCORED_CVE') or True
VULS_MIN_ALERT_SEVERITY  = os.getenv('VULS_MIN_ALERT_SEVERITY') or 'medium'

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

# Reboots required
def reboots_required():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "reboots_required"
    description = "Instances requiring a reboot, see /var/log/pay-reboots-required.log on instances"
    scored = False
    filters = [{'Name':'tag:reboots_required', 'Values':['true']}]
    reservations = EC2_CLIENT.describe_instances(Filters=filters).get('Reservations', [])
    if reservations:
        result = False
        failReason = 'Instances found requiring reboots'
        for instance in reservations:
            instance_name = instance['Instances'][0]['InstanceId']
            for tags in instance['Instances'][0]['Tags']:
                if tags["Key"] == 'Name':
                    instance_name = tags["Value"]
            offenders.append(instance_name)

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


def should_skip_bucket(bucket):
    if S3_BUCKETS_TO_SKIP:
        if bucket['Name'] in S3_BUCKETS_TO_SKIP.split(','):
            return True


# Vuls reports
def vuls_reports():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "vuls_reports"
    description = "Vuls reports"
    scored = False
    cve_summary = dict()
    try:
        today = time.strftime('%Y-%m-%d', time.gmtime(time.time()))
        response = S3_CLIENT.list_objects(Bucket=VULS_REPORT_BUCKET,Prefix=today)
    except Exception as e:
        result = False
        if "AccessDenied" in str(e):
            offenders.append(str(VULS_REPORT_BUCKET) + ":AccessDenied")
            if "Missing" not in failReason:
                failReason = "Missing permissions to " + VULS_REPORT_BUCKET + failReason
        elif "NoSuchBucket" in str(e):
            offenders.append(str(VULS_REPORT_BUCKET) + ":NoBucket")
            if "exist" not in failReason:
                failReason = "Bucket doesn't exist. " + VULS_REPORT_BUCKET + failReason
        else:
            offenders.append(str(VULS_REPORT_BUCKET) + ":Error listing objects")
            failReason = "Error listing objects: " + str(e)
    if response['Contents']:
            for object in response['Contents']:
                  if object['Key'].split('.')[-1] == "json":
                      report = S3_CLIENT.get_object(Bucket=VULS_REPORT_BUCKET,Key=object['Key'])
                      report_body = json.loads(report['Body'].read())
                      known_cves = report_body.get('KnownCves')
                      unknown_cves = report_body.get('UnknownCves')
                      if report_body.get('Optional'):
                          options = dict(report_body['Optional'])
                          if options.get('environment'):
                              env = options.get('environment')
                              if env not in offenders:
                                  offenders.append(env)
                      if known_cves:
                          for known_cve in known_cves:
                              gen_cve_summary(cve_summary,known_cve,report_body['ServerName'])
                      if unknown_cves and VULS_IGNORE_UNSCORED_CVE is False:
                          for unknown_cve in unknown_cves:
                              gen_cve_summary(cve_summary,unknown_cve,report_body['ServerName'])
            final = final_cve_summary(cve_summary)
            if len(final) > 0:
                result = False
                failReason = final
    else:
        result = False
        failReason = "No Vuls reports found for today in " + VULS_REPORT_BUCKET

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

def severity_to_num(severity):
    if severity == 'unknown':
        return 1
    elif severity == 'low':
        return 2
    elif severity == 'medium':
        return 3
    elif severity == 'high':
        return 4


def final_cve_summary(cve_summary):
    for k,v in cve_summary.items():
        if severity_to_num(v['severity']) < severity_to_num(VULS_MIN_ALERT_SEVERITY):
           del cve_summary[k]
    return cve_summary


def gen_cve_summary(summary,cve,servername):
   cve_id = cve['CveDetail']['CveID']
   summary[cve_id] = summary.get(cve_id) or dict()
   if not summary[cve_id].get('score'):
       summary[cve_id]['score'] = cve_score(cve)
   if not summary[cve_id].get('severity'):
       summary[cve_id]['severity'] = cve_severity(summary[cve_id]['score'])
   summary[cve_id]['instances'] = summary[cve_id].get('instances') or []
   summary[cve_id]['instances'].append(servername)


def cve_score(cve):
    if cve['CveDetail']['Nvd']['Score'] > 0:
        return cve['CveDetail']['Nvd']['Score']
    elif cve['CveDetail']['Jvn']['Score'] > 0:
        return cve['CveDetail']['Jvn']['Score']
    else:
        return -1


def cve_severity(cve_score):
    if cve_score >= VULS_HIGH_THRESHOLD:
        return 'high'
    elif cve_score >= VULS_MEDIUM_THRESHOLD:
        return 'medium'
    elif cve_score >= VULS_LOW_THRESHOLD:
        return 'low'
    else:
        return 'unknown'


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
    controls.append(vuls_reports())
    controls.append(reboots_required())

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
