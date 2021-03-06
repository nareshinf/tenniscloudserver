import re
import bz2
import boto3
import json
import uuid
import base64
import logging
from boto3.dynamodb.conditions import Key, Attr
from boto3.dynamodb.types import Binary
from botocore.exceptions import ClientError, ParamValidationError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

print('Loading user function')
dynamo_client = boto3.resource('dynamodb', region_name='us-east-2')
dynamo = dynamo_client.Table('users')

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
                if isinstance(v, Binary):
                    v = v.value
                r[k] = str(v)
    
    return {
        'statusCode': '400' if err else '200',
        'body': err_msg if err_msg else json.dumps(res.get('Items') if isinstance(res, dict) and 'Items' in res.keys() else res),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Headers': 'Origin, Accept, Content-Type, Authorization, Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods': 'DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT'

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
    password = b64_hash_pwd(payload.get('password').encode('utf-8'))
    check_user_pwd = dynamo.scan(FilterExpression=Attr('email').contains(payload.get('email')),
                        ProjectionExpression='password')['Items']
    
    pwd_incorrect = False
    if check_user_pwd:
        for usr_pwd in check_user_pwd:
            if password != usr_pwd.get('password'):
                pwd_incorrect = True
    
    if pwd_incorrect:
        return ("Password is incorrect", False)
        
    check_user = dynamo.scan(
                            FilterExpression=Attr('email').contains(payload.get('email'))\
                                & Attr('password').contains(password),
                            ProjectionExpression='full_name, username, email, id, is_admin'
                            )
    if check_user.get('Items', None):
        res = {k: v for it in check_user.get('Items') for k, v in it.items()}
        return res, True
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

def send_mail_on_register(payload):
    
    to_email, pwd = payload.get('email', None),\
                    payload.get('plain_pwd', None)

    ses_client = boto3.client('ses', region_name='us-east-1')
    
    try:
        response = ses_client.send_email(
                Source='shashanks1@damcogroup.com',
                Destination={
                    'ToAddresses': [
                        '{}'.format(to_email),
                    ]
                },
                Message={
                    'Subject': {
                        'Data': 'Registeration Email'
                    },
                    'Body': {
                        'Text': {
                            'Data': 'Your email {} and password is - {}'.format(to_email, pwd),
                        }
                    }
                }
        )
    except ClientError as e:
        try:
            response = e.response['Error'].get('Message')
        except KeyError as e:
            response = e.message
        
        return response, True
    return response, False

def validate_email(payload):
    
    if isinstance(payload, dict) and "email" not in payload.keys():
        return False, True
    
    if isinstance(payload, dict) and payload['email'] == '':
        return True, False
    
    return False, False

def add_profile_field(payload):
    flds = {
        "office_phone": None,
        "home_phone": None,
        "cell_phone": None,
        "address1": None,
        "address2": None,
        "city": None,
        "user_state": None,
        "country": None,
        "zip": None,
        "height": None,
        "age": None,
        "dob": None,
        "gender": None,
        "preferred_location": None,
        "handedness": None,
        "rating_type": None,
        "rating": None,
        "user_others": None,
        "strength": None,
        "weakness": None,
        "is_admin": False
    }

    payload.update({k:v for k, v in flds.items()})
    return payload


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

            if 'login' in event['path']:
                
                info, resp = user_login(payload)
                if not resp:
                    return respond({"res": info }, {})
                return respond(None, {"res": info })
            
            elif 'forgot-password' in event['path']:
                
                blank, require = validate_email(payload)
                if blank: return respond({"res":"Email is required"}, {})
                if require: return respond({"res":"Email can't be blank"}, {})
                
                email = dynamo.scan(
                                    FilterExpression= Attr('email').contains(payload.get('email')),
                                    ProjectionExpression='password,plain_pwd'
                                )
                if email.get('Count') == 0:
                    return respond({"res": "Provided email address does not exist, please check"}, {})

                pwd = None
                if email.get('Items', None):
                    for obj in email['Items']:
                        pwd = obj['plain_pwd']

                user_pwd = str(pwd)          # dynamo store base64 encoded as binary
                try:
                    resp = forgot_password(payload.get('email'), user_pwd)
                except ClientError as e:
                    return respond({"res": e}, {})
                
                return respond(None, {"res": "Your password has been sent to your authenticated mail successfully"})
            
            elif 'change-password' in event['path']:

                blank, require = validate_email(payload)
                if blank: return respond({"res":"Email is required"}, {})
                if require: return respond({"res":"Email can't be blank"}, {})
                
                if isinstance(payload, dict) and "old_password" not in payload.keys():
                    return respond({"res":"Old password is required"}, {})        
                
                if isinstance(payload, dict) and payload['old_password'] == '':
                    return respond({"res":"Old password can't be blank"}, {})
                
                if str(payload['old_password']) == str(payload['new_password']):
                    return respond({"res":"New password cannot be same as the old password"}, {})

                user_obj = dynamo.scan(FilterExpression= Attr('email').contains(payload.get('email')))
                if user_obj.get('Count') == 0:
                    return respond({"res": "Provided email address does not exist, please check"}, {})

                resource_id, user_pwd = (None,)*2
                for it in user_obj['Items']:
                    resource_id = it.get('id')
                    user_pwd = it.get('plain_pwd')

                old_pwd = payload.get('old_password')
                if str(old_pwd) != user_pwd:
                    return respond({"res": "Your old password does not match"}, {})

                new_plain_pwd = payload.get('new_password')
                new_pwd = b64_hash_pwd(payload.get('new_password').encode('utf-8'))
                
                try:
                    dynamo.update_item(
                        Key={'id': resource_id},
                        UpdateExpression = 'SET password=:pwd, plain_pwd=:pln_pwd',
                        ExpressionAttributeValues = {
                                            ':pwd': new_pwd, 
                                            ':pln_pwd': new_plain_pwd
                                        }
                    )
                except ClientError as e:
                    return respond({"res": e}, {})

                return respond(None, {"res": "Password has been successfully changed. Kindly re-login again to check"})

            else:
                
                source = payload.get('source', 'web')
                blank, require = validate_email(payload)
                if blank: return respond({"res":"Email is required"}, {})
                if require: return respond({"res":"Email can't be blank"}, {})
                
                vld_email = re.match(r'[^@]+@[^@]+\.[^@]+', payload.get('email'))
                if not vld_email:
                    return respond({"res":"Invalid email address"}, {})
                
                if source == 'web':
                    if isinstance(payload, dict) and "password" not in payload.keys():
                        return respond({"res":"password is required"}, {})        
                
                    if isinstance(payload, dict) and payload['password'] == '':
                        return respond({"res":"password can't be blank"}, {})

                    check_email = dynamo.scan(
                                    FilterExpression='email=:em', 
                                    ExpressionAttributeValues={":em": payload.get('email')}
                                )
                    
                    if check_email.get('Items', None):
                        return respond({"res":"Email already exists"}, {})   

                    payload['plain_pwd'] = payload.get('password')
                    payload['password'] = b64_hash_pwd(payload.get('password').encode('utf-8'))
                
                elif source == 'Google':
                    user_exist = dynamo.scan(
                                    FilterExpression=Attr('localId').contains(payload.get('localId')),
                                    ProjectionExpression='full_name, username, email, id'
                                )['Items']
                    
                    if user_exist:
                        res = {k: v for it in user_exist for k, v in it.items()}
                        return respond(None, {"res":res})
                
                # If user record does not exist then create the record
                uid = str(uuid.uuid4())
                payload['id'] = uid
                payload = add_profile_field(payload)
                
                try:
                    create_user = dynamo.put_item(Item=payload)
                except ClientError as e:
                    err_resp = e.response.get('Error') if 'Error' in e.response.keys() else e.message
                    return respond(None, {"res": err_resp.get('Message')})
                
                if create_user:
                    res_inf, err = send_mail_on_register(payload)
                    
                    if source == 'Google':
                        user_detail = dynamo.scan(
                                    FilterExpression=Attr('id').contains(uid),
                                    ProjectionExpression='full_name, username, email, id'
                                )['Items']
                    
                        if user_detail:
                            res = {k: v for it in user_detail for k, v in it.items()}
                            return respond(None, {"res":res})
                    
                    if err:
                        return respond(None, {"res": "User created successfully but system not able to send registration mail,"\
                                                    "as the email address does not verify by system. Please login to continue."})
                    return respond(None, {"res":"User created successfully, please login to continue."})

        elif operation == 'PUT':

            if 'login' in event['path'] or 'forgot-password' in event['path'] or 'change-password' in event['path']:
                return respond({"res": "Method not allowed"}, {})

            # Get path param id
            resource_id = event['pathParameters'] if 'pathParameters' in event.keys() else None
            resource_id = resource_id['proxy'] if isinstance(resource_id, dict) else None
            if not resource_id:
                return respond({"res":"resource id is required"}, {})

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
                
                try:
                    response = e.response['Error'].get('Message')
                except KeyError as e:
                    response = e.message
                
                return respond({"res":response}, {})

        elif operation == 'GET':
            
            if 'login' in event['path'] or 'forgot-password' in event['path'] or 'change-password' in event['path']:
                return respond({"res": "Method not allowed"}, {})

            resource = event['pathParameters'] if 'pathParameters' in event.keys() else None
            resource_id = resource['proxy'] if isinstance(resource, dict) else None
            
            query_string = event.get('queryStringParameters', None)
            if query_string:
                if 'q' in query_string and query_string.get('q') == 'players':
                    data = dynamo.scan(ProjectionExpression='id,full_name,email')
                    return respond(None, data)
            
            if resource_id and 'leagues' in resource_id:
                resource_id = resource_id.split('/')[0]
                league_tbl = dynamo_client.Table('league')
                
                user_details = dynamo.scan(
                                FilterExpression='id=:id', 
                                ExpressionAttributeValues={":id": resource_id},
                                ProjectionExpression='full_name,email'
                            )['Items']
                
                full_name, email = (None,)*2
                for r in user_details:
                    full_name, email = r.get('full_name'), r.get('email')
                
                lg_details = league_tbl.scan(FilterExpression=Attr('groups').exists())['Items']
                reg_lg = []
                if lg_details:
                    for gid, lg in enumerate(lg_details):
                        grp = []
                        # own created laegues by current auth user  
                        if lg.get('created_by') == email:
                            reg_lg.append(lg)
                        else:
                           # registered in other leagues
                            for idx, gr in enumerate(lg.get('groups')):
                                if full_name.lower() in map(str.lower,gr['players']):
                                    grp.append(gr)
                    
                            if grp:
                                lg['groups'] = grp
                                reg_lg.append(lg)
                    return respond(None, {"res": reg_lg})
                return respond({"res": "No league detail found"}, {})
            else:            
                if resource_id:
                    data = dynamo.scan(
                                FilterExpression='id=:id', 
                                ExpressionAttributeValues={":id": resource_id}
                            )                
                    for r in data['Items']:
                        if 'age' in r.keys():
                            r['age'] = str(r['age'])
                    
                        if 'password' in r.keys():
                            del r['password']

                        if 'plain_pwd' in r.keys():
                            del r['plain_pwd']

                    return respond(None, {"res": data.get('Items')[0] if data['Items'] else data['Items'] })
                else:
                    return respond(None, dynamo.scan())

        elif operation == 'OPTIONS':
            return respond({})

        elif operation == 'DELETE':

            if 'login' in event['path'] or 'forgot-password' in event['path'] or 'change-password' in event['path']:
                return respond({"res": "Method not allowed"}, {})

            resource_id = event['pathParameters'] if 'pathParameters' in event.keys() else None
            resource_id = resource_id['proxy'] if isinstance(resource_id, dict) else None
            
            if not resource_id:
                return respond({"res": "Resource id is required"}, {})

            if resource_id:
                data = dynamo.scan(
                            FilterExpression='id=:id', 
                            ExpressionAttributeValues={":id": resource_id},
                            ProjectionExpression='email'
                        )

                email, found = None, False
                for it in data['Items']:
                    email = it.get('email')

                league_tbl = dynamo_client.Table('league')
                # Since there is no lookup {https://forums.aws.amazon.com/thread.jspa?threadID=164470} 
                # available in dynamo api for list, we have to do this manually
                lge_data = filter(lambda x: x!={}, league_tbl.scan(ProjectionExpression='players')['Items'])
                if lge_data:
                    for g in lge_data:
                        if email in g.get('players'):
                            found = True
                            break

                if found:
                    return respond({"res": "Player is involved in one or more league"}, {})

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
        return respond({"res": 'Unsupported method "{}"'.format(operation)}, {})
