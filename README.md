# pay-aws-compliance
The GOV.UK Pay AWS compliance report

## What is it?

[pay-aws-compliance](https://github.com/alphagov/pay-aws-compliance) is
a Python script which runs against an AWS account and checks for things
that fail compliance in some way.

The script can be run independently with

```
python aws_compliance.py
```

or as part of a scheduled Lambda function, or by AWS Config.

## Environment Variables

| Varible | Default | Purpose |
|---------|---------|---------|
|AWS_DEFAULT_REGION | eu-west-1 | AWS Region API client connects to |
|SEND_REPORT_TO_SNS | false | If should send report to SNS |
|SNS_TOPIC_ARN | None | SNS topic ARN to send report to |
|ONLY_SHOW_FAILED | false | Only show failed compliance checks |
|S3_BUCKETS_TO_SKIP| None | CSV of S3 buckets to skip compliance checks |

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
pay-test-foo-bar-badger-bucket do not have logging enabled.
