from __future__ import print_function
from pssh.pssh_client import ParallelSSHClient
from pssh.utils import load_private_key
from IPython import embed
from datetime import datetime
from itertools import groupby

import boto3
import credstash
import csv
import getopt
import json
import os
import paramiko
import re
import sys
import time

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
                    offenders.append(str(credreport[i]['arn']) + ":password")
            except:
                pass  # Never used
        if credreport[i]['access_key_1_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_1_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Credentials unused > 90 days detected. "
                    offenders.append(str(credreport[i]['arn']) + ":key1")
            except:
                pass
        if credreport[i]['access_key_2_active'] == "true":
            try:
                delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_2_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Credentials unused > 90 days detected. "
                    offenders.append(str(credreport[i]['arn']) + ":key2")
            except:
                # Never used
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# Checks unused unix accounts on instances in AWS account
def unused_unix_accounts():
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "unused_unix_accounts"
    description = "Ensure users have logged into Unix accounts in the last 90 days"
    scored = False
   
    instance_filters = [{'Name':'instance-state-name','Values':['running']}]
    instDict=EC2_CLIENT.describe_instances(Filters=instance_filters)

    hostList=[]
    hosts_by_environment = {}
    for r in instDict['Reservations']:
        for inst in r['Instances']:
            for tag in inst['Tags']:
                if tag['Key'] == 'Environment':
                    environment = tag['Value']
                    break
            hostList.append({'ip': inst['PrivateIpAddress'], 'environment': environment})

    for environment, hosts in groupby(hostList, key=lambda hosts: hosts['environment']):
        hosts_by_environment.setdefault(environment, [])
	for host in hosts:
	    hosts_by_environment[environment].append(host['ip'])

    for environment in hosts_by_environment:
        output = ssh_to_hosts(hosts_by_environment[environment],environment,'uptime')
        for host in output:
            for line in output[host]['stdout']:
                print(line)

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


def ssh_to_hosts(hosts,environment,command):
    embed()
    pkey = load_private_key(ssh_key_for_environment(environment))
    try:
        client = ParallelSSHClient(hosts, pkey=pkey, proxy_host=bastion_dns(environment), user='ubuntu')
        output = client.run_command(command)
    return output or {}


def bastion_dns(environment):
    account = environment.split('-')[0]
    prefix = 'admin-' + environment + '.' + account + '.'
    if account in ('production', 'staging'):
        return prefix + 'payments.service.gov.uk'
    else:
        return prefix + 'pymnt.uk'


def ssh_key_for_environment(environment):
    account = environment.split('-')[0]
    credstash_key = account + '.' + environment + '.' + 'ssh_key'
    path_to_key = '/tmp/' + credstash_key
    with open(path_to_key, 'w') as f:
        f.write(credstash.getSecret(credstash_key))
    return path_to_key


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
    report = []
    reader = csv.DictReader(response['Content'].splitlines(), delimiter=',')
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
    cred_report = get_cred_report()

    controls = []
    controls.append(s3_versioning_enabled())
    controls.append(s3_logging_enabled())
    controls.append(vuls_reports())
    controls.append(reboots_required())
    controls.append(root_account_use(cred_report))
    controls.append(mfa_on_password_enabled_iam(cred_report))
    controls.append(unused_credentials(cred_report))
    controls.append(unused_unix_accounts())

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
