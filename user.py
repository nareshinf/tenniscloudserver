import bz2
import boto3
import json
import uuid
import base64
import logging
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError, ParamValidationError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

print('Loading function')
dynamo_client = boto3.resource('dynamodb', region_name='us-east-2')
dynamo = dynamo_client.Table('users')

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
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
    }

def b64_hash_pwd(pwd):
    return base64.b64encode(pwd)

def user_login(payload):
    
    if isinstance(payload, dict) and "email" not in payload.keys():
        return ("Email is required", False)
    
    if isinstance(payload, dict) and payload['email'] == '':
        return ("Email can't be blank", False)
    
    if isinstance(payload, dict) and "password" not in payload.keys():
        return ("Passsword is required", False)
    
    if isinstance(payload, dict) and payload['password'] == '':
        return ("Passsword can't be blank", False)
    
    # encrypt and compare from doc
    password = b64_hash_pwd(payload.get('password'))
    check_user = dynamo.scan(
                            FilterExpression=Attr('email').contains(payload.get('email'))\
                                & Attr('password').contains(password),
                            )
    if check_user.get('Items', None):
        return None, True
    return ("Login information is incorrect", False)

def forgot_password(to_email, pwd):
    
    ses_client = boto3.client('ses', region_name='us-east-1')
    response = ses_client.send_email(
            Source='shashanks1@damcogroup.com',
            Destination={
                'ToAddresses': [
                    '{}'.format(to_email),
                ]
            },
            Message={
                'Subject': {
                    'Data': 'Forgot-Password'
                },
                'Body': {
                    'Text': {
                        'Data': 'Your password is - {}'.format(pwd),
                    }
                }
            }
    )

    return response

def validate_email(payload):
    
    if isinstance(payload, dict) and "email" not in payload.keys():
        return False, True
    
    if isinstance(payload, dict) and payload['email'] == '':
        return True, False
    
    return False, False

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
            # check event for registeration and login

            if 'login' in event['resource']:
                
                err, resp = user_login(payload)
                return respond(None, {"res": resp if resp else err })
            
            elif 'forgot-password' in event['resource']:
                
                blank, require = validate_email(payload)
                if blank: return respond(None, {"res":"Email is required"})
                if require: return respond(None, {"res":"Email can't be blank"})
                
                email = dynamo.scan(
                                    FilterExpression= Attr('email').contains(payload.get('email')),
                                    ProjectionExpression='password'
                                )
                if email.get('Count') == 0:
                    return respond(None, {"res": "Provided email address does not exist, please check"})

                pwd = None
                if email.get('Items', None):
                    for obj in email['Items']:
                        pwd = obj['password']

                user_pwd = base64.b64decode(pwd.value)          # dynamo store base64 encoded as binary
                try:
                    resp = forgot_password(payload.get('email'), user_pwd)
                except ClientError as e:
                    return respond(None, {"res": e})
                
                return respond(None, {"res": "Your password has been sent to your authenticated mail successfully"})
            
            elif 'change-password' in event['resource']:

                blank, require = validate_email(payload)
                if blank: return respond(None, {"res":"Email is required"})
                if require: return respond(None, {"res":"Email can't be blank"})
                
                if isinstance(payload, dict) and "old_password" not in payload.keys():
                    return respond(None, {"res":"Old password is required"})        
                
                if isinstance(payload, dict) and payload['old_password'] == '':
                    return respond(None, {"res":"Old password can't be blank"})

                user_obj = dynamo.scan(FilterExpression= Attr('email').contains(payload.get('email')))
                if user_obj.get('Count') == 0:
                    return respond(None, {"res": "Provided email address does not exist, please check"})

                resource_id, user_pwd = (None,)*2
                for it in user_obj['Items']:
                    resource_id = it.get('id')
                    user_pwd = it.get('password')

                old_pwd = b64_hash_pwd(payload['old_password'].encode('utf-8')).decode('utf-8')
                if str(old_pwd) != user_pwd:
                    return respond(None, {"res": "Your old password does not match"})

                new_pwd = b64_hash_pwd(payload.get('new_password').encode('utf-8'))
                try:
                    dynamo.update_item(
                        Key={'id': resource_id},
                        UpdateExpression = 'SET password=:pwd',
                        ExpressionAttributeValues = {':pwd': new_pwd}
                    )
                except ClientError as e:
                    return respond(None, {"res": e})

                return respond(None, {"res": "Password has been change successfully"})

            else:

                blank, require = validate_email(payload)
                if blank: return respond(None, {"res":"Email is required"})
                if require: return respond(None, {"res":"Email can't be blank"})
                
                if isinstance(payload, dict) and "password" not in payload.keys():
                    return respond(None, {"res":"password is required"})        
                
                if isinstance(payload, dict) and payload['password'] == '':
                    return respond(None, {"res":"password can't be blank"})

                check_email = dynamo.scan(
                                    FilterExpression='email=:em', 
                                    ExpressionAttributeValues={":em": payload.get('email')}
                                )

                if check_email.get('Items', None):
                    return respond(None, {"res":"Email already exists"})   

                payload['id'] = str(uuid.uuid4())
                payload['password'] = b64_hash_pwd(payload.get('password'))

                create_user = dynamo.put_item(Item=payload)
                if create_user:
                    return respond(None, {"res":"user created successfully"})

        elif operation == 'PUT':

            if 'login' in event['resource'] or 'forgot-password' in event['resource']:
                return respond(None, {"res": "Method not allowed"})

            # Get path param id
            resource_id = event['pathParameters'] if 'pathParameters' in event.keys() else None
            resource_id = resource_id['proxy'] if isinstance(resource_id, dict) else None
            if not resource_id:
                return respond(None, {"res":"resource id is required"})

            upt_expr = 'SET '
            for d in payload:
                upt_expr += "{}=:{},".format(d, d)                

            try:
                dynamo.update_item(
                    Key={'id': resource_id},
                    UpdateExpression = upt_expr.rstrip(','),
                    ExpressionAttributeValues = {":"+k:v for k, v in payload.items()}
                )
                return respond(None, {"res":"Updated successfully"})
            except ClientError as e:
                return respond(None, {"res":e})
            
        elif operation == 'GET' or operation == 'OPTIONS':
            
            if 'login' in event['resource'] or 'forgot-password' in event['resource']:
                return respond(None, {"res": "Method not allowed"})

            resource_id = event['pathParameters'] if 'pathParameters' in event.keys() else None
            resource_id = resource_id['proxy'] if isinstance(resource_id, dict) else None
            if resource_id:
                data = dynamo.scan(
                            FilterExpression='id=:id', 
                            ExpressionAttributeValues={":id": resource_id}
                        )                
                for r in data['Items']:
                    if 'age' in r.keys():
                        r['age'] = str(r['age'])
                return respond(None, {"res":data['Items']})
            else:
                return respond(None, dynamo.scan())

        elif operation == 'DELETE':

            resource_id = event['pathParameters'] if 'pathParameters' in event.keys() else None
            resource_id = resource_id['proxy'] if isinstance(resource_id, dict) else None

            if resource_id:
                
                data = dynamo.scan(
                            FilterExpression='id=:id', 
                            ExpressionAttributeValues={":id": resource_id}
                        )

                email = None
                for it in data:
                    email = it.get('email')

                league_tbl = dynamo_client.Table('league')
                lge_data = league_tbl.scan()

                data = dynamo.delete_item(
                            Key={
                                'id': resource_id
                            }
                        )
                 
                return respond(None, {"res": "Player deleted successfully"})

        # try:
        #     return respond(None, operations[operation](dynamo, payload))
        # except ParamValidationError as e:
        #     return respond(e)
        # except ClientError as e:
        #     return respond(e)
    else:
        return respond(ValueError('Unsupported method "{}"'.format(operation)))
