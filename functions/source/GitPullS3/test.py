import boto3

dynamodb = boto3.resource('dynamodb', region_name='eu-west-1')
table = dynamodb.Table('stacks')

#table.put_item(Item={"repo": "webhooks", "data": {"wixit-auth-infrastructure": [], "wixit-auth": [], "wixit-spa": ["feature_code1", "feature_code2"]}})
item = table.get_item(
    Key={
        'repo': 'webhooksa'
    }
)
print(item)
if ("Item" in item):
    print(item["Item"]["data"])