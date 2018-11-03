#!/bin/bash

rm -rf functions/packages
mkdir functions/packages

for dir in functions/source/*
do
    cp -R $dir tmp/
    dir_name=${dir##*/}
    mkdir functions/packages/$dir_name
    cd tmp
    zip -r ../functions/packages/$dir_name/lambda.zip .
    cd ..
    rm -rf tmp/
done

aws s3 cp functions/packages/ s3://wixit-auth-webhooks-lambda-functions/ --recursive
