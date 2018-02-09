import bz2
import boto3
import json
import uuid
import logging
import decimal
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError, ParamValidationError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

print('Loading function')
dynamo_client = boto3.resource('dynamodb', region_name='us-east-2')
dynamo = dynamo_client.Table('league')

def respond(err, res=None):
    err_msg = None
    
    if err:
        err_msg = err.message if hasattr(err, "message") else err
    
    if isinstance(res, dict) and 'Items' in res.keys():
        # minimize decimal issue
        for r in res['Items']:
            for k, v in r.items():
                r[k] = str(v)
    
    
    return {
        'statusCode': '400' if err else '200',
        'body': err_msg if err_msg else json.dumps(res.get('Items') if isinstance(res, dict) and 'Items' in res.keys() else res),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
    }

def lambda_handler(event, context):
    
    logger.info('got event{}'.format(event))
    print("Received event: " + json.dumps(event, indent=2))
    
    operations = {
        'DELETE': lambda dynamo, x: dynamo.delete_item(**x),
        'GET': lambda dynamo, x: dynamo.scan(),
        'POST': lambda dynamo, x: dynamo.put_item(Item=x),
        'PUT': lambda dynamo, x: dynamo.update_item(**x),
        'OPTIONS': lambda dynamo, x: dynamo.scan(),     # added for angular 
    }
        
    operation = event['httpMethod']
    if operation in operations:
        
        body = event['body'] if event['body'] else '{}'
        payload = event['pathParameters'] if operation == 'GET' else json.loads(body)
        
        if operation == 'POST':
            
            # check for primary key validation
            payload['id'] = str(uuid.uuid4())    
            if isinstance(payload, dict) and "name" not in payload.keys():
                return respond(None, {"res":"League name is required"})        
            
            if isinstance(payload, dict) and payload['name'] == '':
                return respond(None, {"res":"League name can't be blank"})
            
            league_exist = dynamo.scan(FilterExpression=Attr('name').contains(payload.get('name')))

            if league_exist.get('Items', None):
                return respond(None, {"res":"League already exists"})   

            create_league = dynamo.put_item(Item=payload)
            if create_league:
                return respond(None, {"res":"league created successfully"})

        elif operation == 'PUT':
            # Get path param id
            
            resource_id = event.get('proxy', None) if 'pathParameters' in event.keys() else None
            if not resource_id:
                return respond(None, {"res":"resource id is required"})

            upt_expr = 'SET '
            for d in payload:
                upt_expr += "{}=:{},".format(d, d)                

            try:
                dynamo.update_item(
                    Key={'id': resource_id},
                    UpdateExpression = upt_expr.rstrip(','),
                    ExpressionAttributeValues = {":"+k:v for k, v in payload.iteritems()}
                )
                return respond(None, {"res":"League updated successfully"})
            except ClientError as e:
                return respond(None, {"res":e})
            
        elif operation == 'GET' or operation == 'OPTIONS':
            resource_id = event.get('proxy', None) if 'pathParameters' in event.keys() else None
            if resource_id:
                data = dynamo.scan(
                            FilterExpression='id=:id', 
                            ExpressionAttributeValues={":id": resource_id}
                        )                
                
                return respond(None, data['Items'])
            else:
                return respond(None, dynamo.scan())

    else:
        return respond(ValueError('Unsupported method "{}"'.format(operation)))
