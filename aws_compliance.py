#!/usr/bin/env python

from __future__ import print_function
import argparse
from datetime import datetime
import csv
import getopt
import json
import os
import pprint
import re
import sys
import time

FALSE_VALUES = ['f', 'false', 'none']

app_description = """
Run AWS compliance reports

Environment variables looked at:

ONLY_SHOW_FAILED
REGION
S3_BUCKETS_TO_SKIP
SEND_REPORT_TO_SNS
SNS_TOPIC_ARN
UNIX_ACCOUNT_REPORT_BUCKET
VULS_REPORT_BUCKET
"""
parser = argparse.ArgumentParser(description=app_description)

parser.add_argument(
    '-e', '--echo',
    action='store_true',
    help='Echoes the args and then exits'
)

parser.add_argument(
    '--only-failed',
    default=str(os.getenv('ONLY_SHOW_FAILED')).lower() not in FALSE_VALUES,
    type=bool,
    help='only show failed'
)

env_region = os.getenv('REGION')
env_region = env_region or os.getenv('AWS_REGION')
env_region = env_region or os.getenv('AWS_DEFAULT_REGION')
env_region = env_region or 'eu-west-1'
parser.add_argument(
    '--region',
    type=str,
    default=env_region,
    help='AWS region; defaults to environment variable or eu-west-1'
)

parser.add_argument(
    '--skip-buckets',
    type=str,
    nargs='*',
    default=[
        s
        for s in ((os.getenv('S3_BUCKETS_TO_SKIP') or '').split(','))
        if len(s)
    ],
    help='list of strs; buckets to skip'
)

parser.add_argument(
    '--send-report-to-sns',
    type=bool,
    default=str(os.getenv('SEND_REPORT_TO_SNS')).lower() not in FALSE_VALUES,
    help='bool; send the report to SNS; default false'
)

parser.add_argument(
    '--sns-topic-arn',
    type=str,
    default=os.getenv('SNS_TOPIC_ARN') or '',
    help='sns topic to send report to; default blank'
)

unix_default_bucket = 'pay-govuk-unix-accounts-dev'
parser.add_argument(
    '--unix-acc-report-bucket',
    type=str,
    default=os.getenv('UNIX_ACCOUNT_REPORT_BUCKET') or unix_default_bucket,
    help='bucket where unix account reports are stored; default {b}'.format(
        b=unix_default_bucket
    )
)

parser.add_argument('--vuls-high-threshold', type=float, default=7,
                    help='vuls high threshold;    default  7')

parser.add_argument('--vuls-medium-threshold', type=float, default=4.5,
                    help='vuls medium threshold;  default  4.5')

parser.add_argument('--vuls-low-threshold', type=float, default=0,
                    help='vuls low threshold;     default  0')

parser.add_argument(
    '--vuls-ignore-unscored',
    type=bool,
    default=str(os.getenv('VULS_IGNORE_UNSCORED_CVE') or True) == 'true',
    help='ignore unscored cves; default true'
)

vuls_min_sev_opts   = ['unknown', 'low', 'medium', 'high']
vuls_min_sev_help_text = """
minimum alert severity; default medium; unknown / low / medium / high
"""
parser.add_argument(
    '--vuls-min-alert-severity',
    type=str,
    default='medium',
    choices=vuls_min_sev_opts,
    help=vuls_min_sev_help_text
)

vuls_bucket = os.getenv('VULS_REPORT_BUCKET') or 'pay-govuk-pay-vuls'
parser.add_argument(
    '--vuls-report-bucket',
    type=str,
    default=vuls_bucket,
    help='bucket where vuls reports are stored; default {b}'.format(
        b='pay-govuk-pay-vuls'
    )
)

args = parser.parse_args()

if args.echo:
    for arg_name, arg_val in vars(args).items():
        if arg_name == 'echo':
            continue
        print('{n} : {v}'.format(n=arg_name.rjust(24), v=str(arg_val)))
    exit(0)

# This should come after the argument parsing.
# This is so you know your command is validated before being asked for MFA.
import botocore
import boto3

EC2_CLIENT = boto3.client('ec2', region_name=args.region)
IAM_CLIENT = boto3.client('iam', region_name=args.region)
S3_CLIENT  = boto3.client('s3',  region_name=args.region)

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
    description = "Instances requiring a reboot, see /var/log/pay-reboots-required.log on instances. See guidance https://pay-team-manual.cloudapps.digital/manual/support/pay-aws-compliance.html#instances-requiring-a-reboot"
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

def root_account_use(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "root_account_use"
    description = "Root account has been logged into - avoid the use of the root account"
    scored = False
    if "Fail" in credreport:  # Report failure in control
        sys.exit(credreport)
    # Check if root is used in the last 24h
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    try:
        pwdDelta = (datetime.strptime(now, frm) - datetime.strptime(credreport[0]['password_last_used'], frm))
        if (pwdDelta.days == 0) & (pwdDelta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = False
    except:
        if credreport[0]['password_last_used'] == "N/A" or "no_information":
            pass
        else:
            print("Something went wrong")

    try:
        key1Delta = (datetime.strptime(now, frm) - datetime.strptime(credreport[0]['access_key_1_last_used_date'], frm))
        if (key1Delta.days == 0) & (key1Delta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = False
    except:
        if credreport[0]['access_key_1_last_used_date'] == "N/A" or "no_information":
            pass
        else:
            print("Something went wrong")
    try:
        key2Delta = datetime.strptime(now, frm) - datetime.strptime(credreport[0]['access_key_2_last_used_date'], frm)
        if (key2Delta.days == 0) & (key2Delta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = False
    except:
        if credreport[0]['access_key_2_last_used_date'] == "N/A" or "no_information":
            pass
        else:
            print("Something went wrong")
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password
def mfa_on_password_enabled_iam(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "mfa_on_password_enabled_iam"
    description = "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password"
    scored = False
    for i in range(len(credreport)):
        # Verify if the user have a password configured
        if credreport[i]['password_enabled'] == "true":
            # Verify if password users have MFA assigned
            if credreport[i]['mfa_active'] == "false":
                result = False
                failReason = "No MFA on users with password. "
                offenders.append(str(credreport[i]['arn']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# Ensure credentials unused for 90 days or greater are disabled
def unused_credentials(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "unused_credentials"
    description = "Ensure credentials unused for 90 days or greater are disabled"
    scored = False
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    # Look for unused credentails
    for i in range(len(credreport)):
        if credreport[i]['password_enabled'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['password_last_used'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Credentials unused > 90 days detected. "
                    offenders.append(f'{str(credreport[i]["arn"])}:password')
            except:
                pass  # Never used
        if credreport[i]['access_key_1_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_1_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Credentials unused > 90 days detected. "
                    offenders.append(f'{str(credreport[i]["arn"])}:key1')
            except:
                pass
        if credreport[i]['access_key_2_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_2_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Credentials unused > 90 days detected. "
                    offenders.append(f'{str(credreport[i]["arn"])}:key2')
            except:
                # Never used
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

def old_api_keys(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "old_api_keys"
    description = "Ensure API keys older than 90 days are rotated."
    scored = False
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    format = "%Y-%m-%dT%H:%M:%S+00:00"

    # Look for unused credentails
    for i in range(len(credreport)):
        if credreport[i]['access_key_1_active'] == "true":
            try:
                delta = datetime.strptime(now, format) - datetime.strptime(credreport[i]['access_key_1_last_rotated'], format)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "API key older than 90 days detected."
                    offenders.append(f'{str(credreport[i]["arn"])}:key1')
            except:
                pass
        if credreport[i]['access_key_2_active'] == "true":
            try:
                delta = datetime.strptime(now, format) - datetime.strptime(credreport[i]['access_key_2_last_rotated'], format)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "API key older than 90 days detected."
                    offenders.append(f'{str(credreport[i]["arn"])}:key2')
            except:
                # Never used
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

def should_skip_bucket(bucket):
    if args.skip_buckets:
        if bucket['Name'] in args.skip_buckets:
            return True


# Unix account last login reports
def unix_account_last_login_reports():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    control = "unix_account_last_login_reports"
    description = "Unix account last login older than 90 days"
    scored = False
    unused_unix_accounts_by_instance = {}
    today = time.strftime('%Y-%m-%d', time.gmtime(time.time()))
    try:
        response = S3_CLIENT.list_objects(Bucket=args.unix_acc_report_bucket,Prefix=today)
        if 'Contents' in response:
            for object in response['Contents']:
                report = S3_CLIENT.get_object(Bucket=args.unix_acc_report_bucket,Key=object['Key'])
                unused_accounts_json = json.loads(report['Body'].read())
                instance = object['Key'].split('__')[0].split('/')[2]
                unused_unix_accounts_by_instance.setdefault(instance, [])
                for account in unused_accounts_json:
                    if account not in unused_unix_accounts_by_instance[instance]:
                        unused_unix_accounts_by_instance[instance].append(account)
            # filter instances less than 90 days
            for instance in list(unused_unix_accounts_by_instance):
                if instance not in instances_in_scope(list(unused_unix_accounts_by_instance)):
                    del unused_unix_accounts_by_instance[instance]
            if len(list(unused_unix_accounts_by_instance)) > 0:
                result = False
                failReason = "Unix accounts found with last login over 90 days ago"
        else:
            result = False
            failReason = "No Unix user account reports found for today in " + args.unix_acc_report_bucket
    except botocore.exceptions.ClientError as error:
        result = False
        failReason = "An error occurred whilst querying the unix user report. " + error.response['Error']['Message']
    return {'Result': result, 'failReason': failReason, 'Offenders': unused_unix_accounts_by_instance, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


def instances_in_scope(instances):
    instances_in_scope = []
    filters = [
      {'Name':'tag:Name', 'Values':instances},
      {'Name':'instance-state-name','Values':['running']}
    ]
    reservations = EC2_CLIENT.describe_instances(Filters=filters).get('Reservations', [])
    for reservation in reservations:
        for instance in reservation['Instances']:
            if launch_time_delta(instance['LaunchTime']) > 90:
                for tags in instance['Tags']:
                    if tags["Key"] == 'Name':
                        instances_in_scope.append(tags["Value"])
    return instances_in_scope


def launch_time_delta(launch_time):
    frm = "%Y-%m-%d %H:%M:%S+00:00"
    now = time.strftime(frm, time.gmtime(time.time()))
    delta = datetime.strptime(now, frm) - datetime.strptime(str(launch_time), frm)
    return delta.days


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
    response = dict()
    try:
        today = time.strftime('%Y-%m-%d', time.gmtime(time.time()))
        response = S3_CLIENT.list_objects(Bucket=args.vuls_report_bucket,Prefix=today)
    except Exception as e:
        result = False
        if "AccessDenied" in str(e):
            offenders.append(str(args.vuls_report_bucket) + ":AccessDenied")
            if "Missing" not in failReason:
                failReason = "Missing permissions to " + args.vuls_report_bucket + failReason
        elif "NoSuchBucket" in str(e):
            offenders.append(str(args.vuls_report_bucket) + ":NoBucket")
            if "exist" not in failReason:
                failReason = "Bucket doesn't exist. " + args.vuls_report_bucket + failReason
        else:
            offenders.append(str(args.vuls_report_bucket) + ":Error listing objects")
            failReason = "Error listing objects: " + str(e)
    if 'Contents' in response:
            for object in response['Contents']:
                  if object['Key'].split('.')[-1] == "json":
                      report = S3_CLIENT.get_object(Bucket=args.vuls_report_bucket,Key=object['Key'])
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
                      if unknown_cves and args.vuls_ignore_unscored is False:
                          for unknown_cve in unknown_cves:
                              gen_cve_summary(cve_summary,unknown_cve,report_body['ServerName'])
            final = final_cve_summary(cve_summary)
            if len(final) > 0:
                result = False
                failReason = final
    else:
        result = False
        failReason = "No Vuls reports found for today in " + args.vuls_report_bucket

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
        if severity_to_num(v['severity']) < severity_to_num(args.vuls_min_alert_severity):
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
    if cve_score >= args.vuls_high_threshold:
        return 'high'
    elif cve_score >= args.vuls_medium_threshold:
        return 'medium'
    elif cve_score >= args.vuls_low_threshold:
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


def get_cred_report():
    """Summary

    Returns:
        TYPE: Description
    """
    x = 0
    status = ""
    while IAM_CLIENT.generate_credential_report()['State'] != "COMPLETE":
        time.sleep(2)
        x += 1
        # If no credentail report is delivered within this time fail the check.
        if x > 10:
            status = "Fail: rootUse - no CredentialReport available."
            break
    if "Fail" in status:
        return status
    response = IAM_CLIENT.get_credential_report()
    responseString = str(response['Content'], 'utf-8').splitlines()
    report = []
    reader = csv.DictReader(responseString, delimiter=',')
    for row in reader:
        report.append(row)
    return report


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
    region = (args.sns_topic_arn.split("sns:", 1)[1]).split(":", 1)[0]
    client = boto3.client('sns', region_name=region)
    subject = "AWS Compliance Report - " + account + " - " + str(time.strftime("%c"))
    body = json.dumps(controls, sort_keys=False, indent=4, separators=(',', ': '))
    response = client.publish(
        TopicArn=args.sns_topic_arn,
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
    cred_report = get_cred_report()

    controls = []
    controls.append(s3_versioning_enabled())
    controls.append(s3_logging_enabled())
    controls.append(vuls_reports())
    controls.append(reboots_required())
    controls.append(root_account_use(cred_report))
    controls.append(mfa_on_password_enabled_iam(cred_report))
    controls.append(unused_credentials(cred_report))
    controls.append(old_api_keys(cred_report))
    controls.append(unix_account_last_login_reports())

    if args.only_failed:
        controls = list(filter(lambda x: x['Result'] == False, controls))

    if args.send_report_to_sns:
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
    boto3.setup_default_session(region_name=args.region)
    lambda_handler("test", "test")
