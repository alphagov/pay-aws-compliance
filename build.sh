#!/bin/bash

set -eo pipefail

VERSION="0.5.0"

IFS=$'\n\t'

if [ -z "$1" ]; then
  echo "Build and upload the compliance lambda to S3 for later deployment"
  echo
  echo "Usage: $0 <S3_BUCKET> [S3_KEY_PREFIX]"
  echo
  echo "  S3_BUCKET is usually either 'pay-govuk-lambda-deploy' or 'pay-govuk-lambda-ci'"
  echo "  S3_KEY_PREFIX defaults to pay-aws-compliance and will be suffixed with the version number"
  echo
  echo "Lambdas in dev, test, and ci are deployed from pay-govuk-lambda-ci"
  echo "Lambdas in deploy, staging, and production are deployed from pay-govuk-lambda-deploy"
  echo "If you wish to deploy a new version you need to run this build twice, once with each of those S3_BUCKET values"
  echo
  exit 1
fi

S3_BUCKET=${1}
S3_KEY=${2:-pay-aws-compliance}

ARTIFACT="${S3_KEY}"-"${VERSION}".zip

TARGET=s3://"${S3_BUCKET}"/"${ARTIFACT}"
TMP_DIR=$(mktemp -d /tmp/lambda-XXXXXX)
ZIPFILE="${TMP_DIR}"/"${ARTIFACT}"

python3 -m venv venv
. ./venv/bin/activate
./venv/bin/python ./venv/bin/pip install -qUr requirements.build.txt

set -u

# The only dependency is boto3 which AWS provides already for us at the versions
# listed in requirements.txt so the only file we need is our python file
zip -r "${ZIPFILE}" aws_compliance.py

aws s3 cp --acl=private "${ZIPFILE}" "${TARGET}"

rm -rf "${TMP_DIR}"
