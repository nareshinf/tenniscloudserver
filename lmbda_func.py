import bz2
import boto3
import json
import logging
from botocore.exceptions import ClientError, ParamValidationError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

print('Loading function')
dynamo_client = boto3.resource('dynamodb', region_name='us-east-2')


def respond(err, res=None):
    err_msg = None
    if err:
        err_msg = err.message if hasattr(err, "message") else err.kwargs
    
    return {
        'statusCode': '400' if err else '200',
        'body': err_msg if err_msg else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }


def lambda_handler(event, context):
    
    logger.info('got event{}'.format(event))
    print("Received event: " + json.dumps(event, indent=2))

    dynamo = dynamo_client.Table('users')
    
    operations = {
        'DELETE': lambda dynamo, x: dynamo.delete_item(**x),
        'GET': lambda dynamo, x: dynamo.scan(),
        'POST': lambda dynamo, x: dynamo.put_item(Item=x),
        'PUT': lambda dynamo, x: dynamo.update_item(**x),
    }
        
    operation = event['httpMethod']
    if operation in operations:
        payload = event['queryStringParameters'] if operation == 'GET' else json.loads(event['body'])
        try:
            return respond(None, operations[operation](dynamo, payload))
        except ParamValidationError as e:
            return respond(e)
        except ClientError as e:
            return respond(e)
    else:
        return respond(ValueError('Unsupported method "{}"'.format(operation)))
