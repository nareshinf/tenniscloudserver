import bz2
import boto3
import json
import uuid
import logging
import decimal
from datetime import datetime
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
        if isinstance(err_msg, dict):
            err_msg = json.dumps(err_msg)

    if isinstance(res, dict) and 'Items' in res.keys():
        # minimize decimal issue
        for r in res['Items']:
            for k, v in r.items():
                if isinstance(v, decimal.Decimal):
                    v = str(v)
                r[k] = str(v)
    
    
    return {
        'statusCode': '400' if err else '200',
        'body': err_msg if err_msg else json.dumps(res.get('Items') if isinstance(res, dict) and 'Items' in res.keys() else res),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Headers': 'Origin, Accept, Content-Type, Authorization, Access-Control-Allow-Origin'
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
                return respond({"res":"League name is required"}, {})        
            
            if isinstance(payload, dict) and payload['name'] == '':
                return respond({"res":"League name can't be blank"}, {})
            
            league_exist = dynamo.scan(FilterExpression=Attr('name').contains(payload.get('name')))

            if league_exist.get('Items', None):
                return respond({"res":"League already exists"}, {})   

            payload['created'] = str(datetime.now().date())
            create_league = dynamo.put_item(Item=payload)
            if create_league:
                return respond(None, {"res":"League created successfully"})

        elif operation == 'PUT':
            # Get path param id
            
            resource_id = event['pathParameters'] if 'pathParameters' in event.keys() else None
            resource_id = resource_id['proxy'] if isinstance(resource_id, dict) else None
            if not resource_id:
                return respond({"res":"Resource Id is required"}, {})

            upt_expr = 'SET '
            for d in payload:
                upt_expr += "{}=:{},".format(d, d)                

            try:
                dynamo.update_item(
                    Key={'id': resource_id},
                    UpdateExpression = upt_expr.rstrip(','),
                    ExpressionAttributeValues = {":"+k:v for k, v in payload.items()}
                )
                return respond(None, {"res":"League updated successfully"})
            except ClientError as e:
                try:
                    response = e.response['Error'].get('Message')
                except KeyError as e:
                    response = e.message
        
                return respond({"res":response}, {})
            
        elif operation == 'GET':
            
            resource_id = event['pathParameters'] if 'pathParameters' in event.keys() else None
            resource_id = resource_id['proxy'] if isinstance(resource_id, dict) else None
            
            if resource_id:
                data = dynamo.scan(
                            FilterExpression='id=:id', 
                            ExpressionAttributeValues={":id": resource_id}
                        )                
                
                return respond(None, data['Items'])
            else:
                data = dynamo.scan()
                for it in data['Items']:
                    pl=[]
                    if 'groups' in it.keys():
                        for p in it['groups']:
                            pl.extend(p.get('players'))
                        it['players'] = pl
                        del it['groups']

                return respond(None, data)

        elif operation == 'OPTIONS':
            return respond({})

        elif operation == 'DELETE':
            if event['resource'] in ['login', 'forgot-password', 'change-password']:
                return respond(None, {"res": "Method not allowed"})

            resource_id = event['pathParameters'] if 'pathParameters' in event.keys() else None
            resource_id = resource_id['proxy'] if isinstance(resource_id, dict) else None

            if not resource_id:
                return respond({"res": "Resource id is required"}, {})

            if resource_id:
                
                league_tbl = dynamo_client.Table('league')
                data = league_tbl.delete_item(
                            Key={
                                'id': resource_id
                            }
                        )
                 
                return respond(None, {"res": "League deleted successfully"})


    else:
        return respond(ValueError('Unsupported method "{}"'.format(operation)))
