
import boto3
import json
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

print('Loading function')


def respond(err, res=None):
    return {
        'statusCode': '400' if err else '200',
        'body': err.message if err else json.dumps(res),
        'headers': {
            'Content-Type': 'application/json',
        },
    }


def lambda_handler(event, context):

    logger.info('got event{}'.format(event))
    print("Received event: " + json.dumps(event, indent=2))

    operations = {
        'GET': lambda x: x
    }

    operation = event['httpMethod']
    print("operations", operation)
    if operation in operations:
        payload = event['queryStringParameters'] if operation == 'GET' else json.loads(event['body'])
        return respond(None, operations[operation](payload))
    else:
        return respond(ValueError('Unsupported method "{}"'.format(operation)))
