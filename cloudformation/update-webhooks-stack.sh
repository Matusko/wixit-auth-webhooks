#!/bin/bash

aws cloudformation update-stack \
    --capabilities CAPABILITY_NAMED_IAM \
    --region eu-west-1 \
    --stack-name wixit-auth-webhooks \
    --template-body file://webhooks.yaml \
    --parameters file://webhooks-params.json
