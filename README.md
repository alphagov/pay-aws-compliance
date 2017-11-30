# pay-aws-compliance
The GOV.UK Pay AWS compliance report

## What is it?

[pay-aws-compliance](https://github.com/alphagov/pay-aws-compliance) is
a Python script which runs against an AWS account and checks for things
that fail compliance in some way.

The script can be run independently with

```
./aws_compliance.py -h # Help message
./aws_compliance.py -e # Dry-run: echo variables
./aws_compliance.py    # Run the reports
```

or as part of a scheduled Lambda function, or by AWS Config.

## Controls

|control_id|description|
|:-:|---|
|s3\_versioning\_enabled|Checks all buckets in an S3 account for bucket versioning being enabled|
|3\_logging\_enabled|Checks all buckets in an S3 account for bucket logging being enabled|
|vuls_reports|Scans nightly generated Vuls reports and alerts if CVE found|
|reboots_required|pay-reboots-required runs and updates the instance `reboot_required` tag nightly. This control checks for instance tags of `reboots_required: true`|

## Environment Variables

| Varible | Default | Purpose |
|---------|---------|---------|
|AWS\_DEFAULT\_REGION | eu-west-1 | AWS Region API client connects to |
|SEND\_REPORT\_TO_SNS | false | If should send report to SNS |
|SNS\_TOPIC\_ARN | None | SNS topic ARN to send report to |
|ONLY\_SHOW\_FAILED | false | Only show failed compliance checks |
|S3\_BUCKETS\_TO_SKIP | None | CSV of S3 buckets to skip compliance checks |
|VULS\_REPORT\_BUCKET | pay-govuk-dev-vuls | S3 bucket to find Vuls reports |
|UNIX\_ACCOUNT\_REPORT\_BUCKET | pay-govuk-unix-accounts-dev | S3 bucket where unix account reports are stored |

## Interpreting the compliance report

Interpreting the compliance report should be pretty straight forward:

```
python aws_compliance.py
[
    {
        "Description": "Ensure S3 versioning is enabled on all buckets",
        "ScoredControl": false,
        "failReason": "",
        "Result": true,
        "Offenders": [],
        "ControlId": "s3_versioning_enabled"
    },
    {
        "Description": "Ensure S3 logging is enabled on all buckets",
        "ScoredControl": false,
        "failReason": "",
        "Result": true,
        "Offenders": [],
        "ControlId": "s3_logging_enabled"
    }
]
```

The above shows output for an AWS account which is not in violation of
any of the compliance controls.

```
python aws_compliance.py
[
    {
        "Description": "Ensure S3 versioning is enabled on all buckets",
        "ScoredControl": false,
        "failReason": "Buckets found without versioning enabled",
        "Result": false,
        "Offenders": [
            "pay-test-foo-bar-bucket"
        ],
        "ControlId": "s3_versioning_enabled"
    },
    {
        "Description": "Ensure S3 logging is enabled on all buckets",
        "ScoredControl": false,
        "failReason": "Buckets found without logging enabled",
        "Result": false,
        "Offenders": [
            "pay-test-foo-bar-bucket"
            "pay-test-foo-bar-badger-bucket"
        ],
        "ControlId": "s3_logging_enabled"
    },
    {
        "Description": "Vuls reports",
        "ScoredControl": false,
        "failReason": {
            "CVE-2017-7484": {
                "instances": [
                    "badger-12-egress-proxy-i-111111111111",
                    "foo-12-egress-proxy-i-999999999999"
                ],
                "score": 5,
                "severity": "high"
            },
            "CVE-2017-7485": {
                "instances": [
                    "badger-12-egress-proxy-i-111111111111",
                    "foo-12-egress-proxy-i-999999999999"
                ],
                "score": 4.3,
                "severity": "high"
            },
            "CVE-2017-7486": {
                "instances": [
                    "badger-12-egress-proxy-i-111111111111",
                    "foo-12-egress-proxy-i-999999999999"
                ],
                "score": 5,
                "severity": "high"
            }
        },
        "Result": false,
        "Offenders": [
            "dev-josh-23"
        ],
        "ControlId": "vuls_reports"
    }
]
```

The above shows output for an AWS account which _is_ in violation of
several of the compliance controls.

If something is in violation of the compliance controls, there should
be a human understandable `failReason` in the report, followed by the
`ControlId` and a list of `Offenders`

In the above example, the S3 bucket pay-test-foo-bar-bucket does not
have versioning enabled and the S3 buckets pay-test-foo-bar-bucket +
pay-test-foo-bar-badger-bucket do not have logging enabled. There are
also a number of CVEs in the test-12 environment
