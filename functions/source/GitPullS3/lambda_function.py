#  Copyright 2016 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#  This file is licensed to you under the AWS Customer Agreement (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at http://aws.amazon.com/agreement/ .
#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
#  See the License for the specific language governing permissions and limitations under the License.

from boto3 import client, resource
import os
import shutil
from ipaddress import ip_network, ip_address
import logging
import hmac
import hashlib
import botocore
import json
import threading

s3 = client('s3', region_name='eu-west-1')
cloudformation = client('cloudformation', region_name='eu-west-1')
branches_deployment_state_file = 'branches_deployment_state.json'
webhhoks_configs_s3_bucket_name = 'webhooks-configs-and-templates'
configs = {
    'wixit-auth-infrastructure': {
        'params': 'wixit-auth-infrastructure/microservice-pipeline-params-without-variables.json',
        'template': 'wixit-auth-infrastructure/microservice-pipeline.yaml',
        'stack-name-prefix': 'wixit-auth-infrastructure',
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
        'stack-name-prefix': 'wixit-auth',
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
        'stack-name-prefix': 'wixit-spa',
        'branch-key': 'GitHubBranch',
        'artifact-store-key': '',
        'context-path-key': 'BaseHref',
        'infrastructure-key': '',
        'infrastructure': '',
        'stage-level-key': 'StageLevel'
    }
}

# If true the function will not include .git folder in the zip
exclude_git = True

# If true the function will delete all files at the end of each invocation, useful if you run into storage space
# constraints, but will slow down invocations as each invoke will need to checkout the entire repo
cleanup = False

key = 'enc_key'

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
    return configs[repo]['stack-name-prefix'] + '-' + branch_name_key_part + '-' + suffix

def create_stack(repo, branch_name):
    s3.download_file(webhhoks_configs_s3_bucket_name, branches_deployment_state_file, '/tmp/' + branches_deployment_state_file)

    with open('/tmp/' + branches_deployment_state_file) as file:
        branches_deployment_state = json.load(file)
    config = configs[repo]
    if (repo in branches_deployment_state and branch_name in branches_deployment_state[repo]):
        print ('branch already deployed')
    elif (config['infrastructure'] and (config['infrastructure'] not in branches_deployment_state or branch_name not in branches_deployment_state[config['infrastructure']])):
        print ('infrastructure dependency not satisfied')
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

            template_file_s3 = config['template']
            param_file_s3 = config['params']
            template_file = '/tmp/' + os.path.basename(template_file_s3)
            param_file = '/tmp/' + os.path.basename(param_file_s3)
            stack_name = config['stack-name-prefix'] + '-' + branch_name_key_part

            s3.download_file(webhhoks_configs_s3_bucket_name, template_file_s3, template_file)
            s3.download_file(webhhoks_configs_s3_bucket_name, param_file_s3, param_file)

            with open(param_file) as f:
                data = json.load(f)
            if config['branch-key']:
                branch_param = {
                    "ParameterKey": config['branch-key'],
                    "ParameterValue": branch_name
                }
                data.append(branch_param)

            if config['artifact-store-key']:
                templates_s3_bucket_param = {
                    "ParameterKey": config['artifact-store-key'],
                    "ParameterValue": get_artifacts_bucket_name(repo, branch_name_key_part)
                }
                data.append(templates_s3_bucket_param)

            if config['context-path-key']:
                context_path_param = {
                    "ParameterKey": config['context-path-key'],
                    "ParameterValue": "/" + branch_name_key_part
                }
                data.append(context_path_param)

            if config['infrastructure-key']:
                context_path_param = {
                    "ParameterKey": config['infrastructure-key'],
                    "ParameterValue": config['infrastructure'] + '-' + branch_name_key_part
                }
                data.append(context_path_param)

            if config['stage-level-key']:
                stage_level_param = {
                    "ParameterKey": config['stage-level-key'],
                    "ParameterValue": stage_level
                }
                data.append(stage_level_param)

            with open(template_file) as yaml_data:
                template = yaml_data.read()

            cloudformation.create_stack(StackName = stack_name, TemplateBody = template, Parameters = data, Capabilities = ['CAPABILITY_NAMED_IAM',])

            os.remove(template_file)
            os.remove(param_file)

            if (repo in branches_deployment_state):
                branches_deployment_state[repo].append(branch_name)
            else:
                branches_deployment_state[repo] = [branch_name,]

            with open('/tmp/' + branches_deployment_state_file, 'w') as outfile:
                json.dump(branches_deployment_state, outfile)
            s3.upload_file('/tmp/' + branches_deployment_state_file, webhhoks_configs_s3_bucket_name, branches_deployment_state_file)

    os.remove('/tmp/' + branches_deployment_state_file)

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
            print("...waiting too long")
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

    stack_name = configs[repo]['stack-name-prefix'] + '-' + branch_name_key_part
    if stack_name in existing_stacks:
        delete_bucket(get_artifacts_bucket_name(repo, branch_name_key_part))
        cloudformation.delete_stack(StackName=stack_name)

        s3.download_file(webhhoks_configs_s3_bucket_name, branches_deployment_state_file, '/tmp/' + branches_deployment_state_file)
        new_branches_deployment_state_file = 'new_' + branches_deployment_state_file

        with open('/tmp/' + branches_deployment_state_file, 'r') as file:
            branches_deployment_state = json.load(file)
            branches_deployment_state[repo].remove(branch_name)
            with open('/tmp/' + new_branches_deployment_state_file, 'w') as file2:
                json.dump(branches_deployment_state, file2)
            s3.upload_file('/tmp/' + new_branches_deployment_state_file, webhhoks_configs_s3_bucket_name, branches_deployment_state_file)

        os.remove('/tmp/' + branches_deployment_state_file)
        os.remove('/tmp/' + new_branches_deployment_state_file)

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
    # TODO: Add the ability to clone TFS repo using SSH keys
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

    logger.info('INFOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO')
    logger.info(repo_name)
    logger.info(branch_name)

    if event['params']['header']['X-GitHub-Event'] == 'delete':
        delete_stack(os.path.basename(full_name), branch_name)
    else:
        create_stack(os.path.basename(full_name), branch_name)

    if cleanup:
        logger.info('Cleanup Lambda container...')
        shutil.rmtree(repo_path)
        os.remove('/tmp/id_rsa')
        os.remove('/tmp/id_rsa.pub')
    return 'Successfully updated %s' % repo_name

