import boto3
from boto3 import client, resource, session
from botocore.exceptions import ClientError
import os
import shutil
from ipaddress import ip_network, ip_address
import logging
import hmac
import hashlib
import botocore
import base64
import json
import threading
from pygit2 import clone_repository

s3 = client('s3', region_name='eu-west-1')
cloudformation = client('cloudformation', region_name='eu-west-1')
dynamodb = boto3.resource('dynamodb', region_name='eu-west-1')
table = dynamodb.Table('stacks')
configs = {
    'wixit-auth-infrastructure': {
        'params': 'wixit-auth-infrastructure/microservice-pipeline-params-without-variables.json',
        'template': 'wixit-auth-infrastructure/microservice-pipeline.yaml',
        'branch-key': 'GitHubInfrastructureBranch',
        'artifact-store-key': 'ArtifactStoreS3Location',
        'context-path-key': 'ContextPath',
        'infrastructure-key': '',
        'infrastructure': '',
        'stage-level-key': 'StageLevel'
    },
    'wixit-auth': {
        'params': 'wixit-auth/deployment-pipeline-params-without-variables.json',
        'template': 'wixit-auth/deployment-pipeline.yaml',
        'branch-key': 'GitHubBranch',
        'artifact-store-key': 'MicroserviceArtifactStoreS3Location',
        'context-path-key': '',
        'infrastructure-key': 'AuthInfrastructureStackName',
        'infrastructure': 'wixit-auth-infrastructure',
        'stage-level-key': 'StageLevel'
    },
    'wixit-spa': {
        'params': 'wixit-spa/pipeline-params-without-variables.json',
        'template': 'wixit-spa/pipeline.yaml',
        'branch-key': 'GitHubBranch',
        'artifact-store-key': '',
        'context-path-key': 'BaseHref',
        'infrastructure-key': '',
        'infrastructure': '',
        'stage-level-key': 'StageLevel'
    }
}

key = 'enc_key'
tmp_repo_path = '/tmp/repo'

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.handlers[0].setFormatter(logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s'))
logging.getLogger('boto3').setLevel(logging.ERROR)
logging.getLogger('botocore').setLevel(logging.ERROR)

kms = client('kms')

def get_branch_name_key_part(branch_name):
    branch_name_key_part = branch_name
    branch_name_prefix_part = ''
    if "_" in branch_name_key_part:
        branch_name_prefix_part, branch_name_key_part = branch_name_key_part.split("_", 1)

    return branch_name_prefix_part, branch_name_key_part

def get_artifacts_bucket_name(repo, branch_name_key_part):
    return repo + '-' + branch_name_key_part + "-artifacts"

def stack_set_name(repo, branch_name_key_part, suffix):
    return repo + '-' + branch_name_key_part + '-' + suffix

def create_stack(repo, branch_name):
    item = table.get_item(Key={'repo': 'webhooks'})

    if ("Item" in item):
        branches_deployment_state = item["Item"]["data"]

    else:
        table.put_item(Item={"repo": "webhooks", "data": {}})
        item = table.get_item(Key={'repo': 'webhooks'})
        branches_deployment_state = item["Item"]["data"]

    if (repo in branches_deployment_state and branch_name in branches_deployment_state[repo]):
        logger.info('branch already deployed')
    else:
        clone_repository('https://github.com/Matusko/wixit-spa.git', tmp_repo_path, checkout_branch=branch_name)

        with open(tmp_repo_path + '/webhooks/config.json') as file:
            webhook_repo_config = json.load(file)

        if (webhook_repo_config['infrastructure'] and (webhook_repo_config['infrastructure'] not in branches_deployment_state or branch_name not in branches_deployment_state[webhook_repo_config['infrastructure']])):
            logger.info('infrastructure dependency not satisfied')
        else:
            branch_name_prefix_part, branch_name_key_part = get_branch_name_key_part(branch_name)

            stage_level = None

            if branch_name_prefix_part == 'task':
                stage_level = 'test'
            if branch_name_prefix_part == 'feature':
                stage_level = 'dev'
            if branch_name_prefix_part == 'release':
                stage_level = 'prod'

            if stage_level is not None:
                stack_name = repo + '-' + branch_name_key_part

                with open(tmp_repo_path + '/' + webhook_repo_config['params']) as f:
                    data_str = f.read()

                    data_str = data_str.replace("GIT_HUB_BRANCH", branch_name)
                    data_str = data_str.replace("GIT_HUB_TOKEN", get_github_token())
                    data_str = data_str.replace("CONTEXT_PATH",  "/" + branch_name_key_part)
                    data_str = data_str.replace("STAGE_LEVEL", stage_level)
                    data_str = data_str.replace("INFRASTRUCTURE", webhook_repo_config['infrastructure'] + '-' + branch_name_key_part)
                    data_str = data_str.replace("ARTIFACT_STORE", get_artifacts_bucket_name(repo, branch_name_key_part))

                    data = json.loads(data_str)

                with open(tmp_repo_path + '/' + webhook_repo_config['template']) as yaml_data:
                    template = yaml_data.read()

                cloudformation.create_stack(StackName = stack_name, TemplateBody = template, Parameters = data, Capabilities = ['CAPABILITY_NAMED_IAM',])

                if (repo in branches_deployment_state):
                    branches_deployment_state[repo].append(branch_name)
                else:
                    branches_deployment_state[repo] = [branch_name,]

                table.put_item(Item={"repo": "webhooks", "data": branches_deployment_state})

    if os.path.exists(tmp_repo_path) and os.path.isdir(tmp_repo_path):
        shutil.rmtree(tmp_repo_path)

def delete_bucket(bucket_name):
    s3_resource = resource('s3')
    bucket = s3_resource.Bucket(bucket_name)
    bucket.objects.all().delete()
    bucket.delete()

def call_script(repo, branch_name_key_part, stack_suffix, existing_stacks):
    stack_name = stack_set_name(repo, branch_name_key_part, stack_suffix)
    if stack_name in existing_stacks:
        cloudformation.delete_stack(StackName=stack_name)
        try:
            waiter = cloudformation.get_waiter('stack_delete_complete')
            waiter.wait(StackName=stack_name)
        except botocore.exceptions.ClientError as ex:
            logger.info("...waiting too long")
    return

def delete_stack(repo, branch_name):
    branch_name_prefix_part, branch_name_key_part = get_branch_name_key_part(branch_name)

    existing_stacks = list(map(lambda stack:stack['StackName'], cloudformation.describe_stacks()['Stacks']))

    t1 = threading.Thread(target=call_script, args=(repo, branch_name_key_part, 'DEV', existing_stacks))
    t2 = threading.Thread(target=call_script, args=(repo, branch_name_key_part, 'UAT', existing_stacks))
    t3 = threading.Thread(target=call_script, args=(repo, branch_name_key_part, 'PROD', existing_stacks))

    t1.start()
    t2.start()
    t3.start()

    t1.join()
    t2.join()
    t3.join()

    stack_name = repo + '-' + branch_name_key_part
    if stack_name in existing_stacks:
        delete_bucket(get_artifacts_bucket_name(repo, branch_name_key_part))
        cloudformation.delete_stack(StackName=stack_name)

        item = table.get_item(Key={'repo': 'webhooks'})

        if ("Item" in item):
            branches_deployment_state = item["Item"]["data"]

        else:
            table.put_item(Item={"repo": "webhooks", "data": {}})
            item = table.get_item(Key={'repo': 'webhooks'})
            branches_deployment_state = item["Item"]["data"]

        branches_deployment_state[repo].remove(branch_name)
        table.put_item(Item={"repo": "webhooks", "data": branches_deployment_state})

def get_github_token():

    secret_name = "GitHubToken"
    region_name = "eu-west-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])

    return json.loads(secret)['GitHubToken']

def lambda_handler(event, context):
    # Source IP ranges to allow requests from, if the IP is in one of these the request will not be chacked for an api key
    ipranges = []
    for i in event['context']['allowed-ips'].split(','):
        ipranges.append(ip_network(u'%s' % i))
    # APIKeys, it is recommended to use a different API key for each repo that uses this function
    apikeys = event['context']['api-secrets'].split(',')
    ip = ip_address(event['context']['source-ip'])
    secure = False
    for net in ipranges:
        if ip in net:
            secure = True
    if 'X-Gitlab-Token' in event['params']['header'].keys():
        if event['params']['header']['X-Gitlab-Token'] in apikeys:
            secure = True
    if 'X-Git-Token' in event['params']['header'].keys():
        if event['params']['header']['X-Git-Token'] in apikeys:
            secure = True
    if 'X-Gitlab-Token' in event['params']['header'].keys():
        if event['params']['header']['X-Gitlab-Token'] in apikeys:
            secure = True
    if 'X-Hub-Signature' in event['params']['header'].keys():
        for k in apikeys:
            k1 = hmac.new(str(k), str(event['context']['raw-body']), hashlib.sha1).hexdigest()
            k2 = str(event['params']['header']['X-Hub-Signature'].replace('sha1=', ''))
            if k1 == k2:
                secure = True
    logger.info("EVENT INFO")
    logger.info(json.dumps(event))
    try:
        full_name = event['body-json']['repository']['full_name']
    except KeyError:
        try:
            full_name = event['body-json']['repository']['fullName']
        except KeyError:
            full_name = event['body-json']['repository']['path_with_namespace']
    if not secure:
        logger.error('Source IP %s is not allowed' % event['context']['source-ip'])
        raise Exception('Source IP %s is not allowed' % event['context']['source-ip'])

    if('action' in event['body-json'] and event['body-json']['action'] == 'published'):
        branch_name = 'tags/%s' % event['body-json']['release']['tag_name']
        repo_name = full_name + '/release'
    else:
        try:
            branch_name = 'master'
            repo_name = event['body-json']['project']['path_with_namespace']
        except:
            if 'ref' in event['body-json']:
                branch_name = event['body-json']['ref'].replace('refs/heads/', '')
            else:
                branch_name = 'master'
            repo_name = full_name + '/branch/' + branch_name
    repo_path = '/tmp/%s' % repo_name

    logger.info('BASIC INFOOOOO')
    logger.info(repo_name)
    logger.info(branch_name)

    if event['params']['header']['X-GitHub-Event'] == 'delete':
        logger.info('DELETE STACK')
        delete_stack(os.path.basename(full_name), branch_name)
    else:
        logger.info('CREATE STACK')
        create_stack(os.path.basename(full_name), branch_name)

    return 'Successfully updated %s' % repo_name

