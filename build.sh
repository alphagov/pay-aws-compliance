#!/bin/bash

set -eo pipefail

VERSION="0.3.0"

IFS=$'\n\t'

if [ -z "$1" ]; then
  echo "Usage: $0 <S3_BUCKET> [S3_KEY_PREFIX]"
  echo
  echo "  S3_BUCKET is usually either 'pay-govuk-lambda-deploy' or 'pay-govuk-lambda-ci'"
  echo "  S3_KEY_PREFIX defaults to pay-aws-compliance and will be suffixed with the version number"
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
