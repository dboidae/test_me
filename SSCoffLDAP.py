#!/usr/bin/python3
#
import  json
import  configparser
import  ldap3
from    botocore.vendored import requests
from    botocore.exceptions import ClientError
import  boto3
import  logging

ERROR = 2
HTTP_OK = 200
HTTP_Unauthorized = 401
HTTP_DELETE_CODE = 204
ERROR_LDAP_LOCKED = 250
ERROR_LDAP_NOT_FOUND = 254

FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s \n"
logger = logging.getLogger()
for h in logger.handlers:
    h.setFormatter(logging.Formatter(FORMAT))
logger.setLevel(logging.WARNING)


def open_ldap(host, user, password):
    s = ldap3.Server(host, get_info=ldap3.ALL, connect_timeout=5)
    return ldap3.Connection(s, user=user, password=password, auto_bind=True)


def test_ldap_searchable(conn, base, check_user):
    search_filter = '(mail={})'.format(check_user)
    conn.search(base, search_filter, attributes=['mail'])
    if len(conn.response) == 0:
        return False
    else:
        if "mail" in conn.response[0]['attributes']:
            return True


def test_ldap_user_exist(conn, base, ldap_filter, check_user):
    search_filter = ldap_filter.format(check_user)
    search_filter_email_only = '(mail={})'.format(check_user)
    conn.search(base, search_filter_email_only, attributes=['mail'])
    if len(conn.response) == 0:
        return ERROR_LDAP_NOT_FOUND
    else:
        conn.search(base, search_filter, attributes=['nsaccountlock'])
        if len(conn.response) == 0:
            return ERROR_LDAP_LOCKED
        else:
            if ('true' in conn.response[0]['attributes']['nsaccountlock']):
                return ERROR_LDAP_LOCKED
            else:
                logger.info(conn.response[0]['attributes']['nsaccountlock'])
                return True


def ses_send_email(config, email_body):
    ses = boto3.client('ses')
    response = ses.send_email(
        Source = config['EMAIL']['from'],
        Destination={
            'ToAddresses': [
                config['EMAIL']['to'],
            ]
        },
        Message={
            'Subject': {
                'Data': config['EMAIL']['subj']
            },
            'Body': {
                'Text': {
                    'Data': email_body
                }
            }
        }
    )
    return response
    

# Initial setup
def init_cfg(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    if (config['AWS']['SSC_use_secret_manager'] == '1'):
        secret = get_secret(config, config['AWS']['SSC_API_secret'])
        if not secret:
            logger.error('cannot retrive secret SSC - exit')
            return None
        data = json.loads(secret)
        for key, value in data.items():
            config['SSC']['API_email'] = key
            config['SSC']['API_password'] = value
    if (config['AWS']['LDAP_use_secret_manager'] == '1'):
        secret = get_secret(config, config['AWS']['SSC_LDAP_secret'])
        if (secret == None):
            logger.error('cannot retrive secret ldap - exit')
            return None
        data = json.loads(secret)
        for key, value in data.items():
            config['LDAP']['LDAP_user_or_DN'] = key
            config['LDAP']['LDAP_password'] = value
    return config


# Authenticate
def connection_to_ssc(config):
    auth = requests.post(config['SSC']['API_url'] + '/auth', data = {"email": config['SSC']['API_email'], "password": config['SSC']['API_password']},timeout=10)
    if (auth.status_code == HTTP_Unauthorized):
        logger.error('invalid SSC login')
        return False, False
    if (auth.status_code != HTTP_OK):
        logger.error('SSC - Unexpected login status')
        logger.error(auth.status_code)
        return False, False
    parsed_response = auth.json()
    token = parsed_response['token']
    headers = {'Content-type': 'application/json','Authorization': 'Bearer %s' % token}
    logger.info('SSC site headers')
    logger.info(headers)
    users = requests.get(config['SSC']['API_url'] + '/corps/' + config['SSC']['corp_name'] + '/users', headers=headers,timeout=10)
    return users.json(), headers


def delete_user_from_ssc(config, headers, email):
    try:
        delete_user = requests.delete(config['SSC']['API_url'] + '/corps/' + config['SSC']['corp_name'] + '/users/' + email, headers=headers, timeout=45)
        logger.warning(delete_user.status_code)
        if (delete_user.status_code == HTTP_DELETE_CODE): return True
        return
    except:
        return False
        

# try connect to LDAP
def test_ldap_open(config):
    conn = open_ldap(config['LDAP']['LDAP_server'], config['LDAP']['LDAP_user_or_DN'], config['LDAP']['LDAP_password'])
    logger.info(conn)
# try search inside base LDAP
    try:
        ldap_user = test_ldap_searchable(conn, config['LDAP']['LDAP_base'], config['LDAP']['LDAP_test_account'])
        logger.info('ldap_searchable test return ' + str(ldap_user))
    except:
        logger.error('ldap test_account autorization error - exit')
        return False
# if required account exist
    if ldap_user:
        logger.info('ldap test passed')
    else:
        logger.error('cannot search in the LDAP base ' + config['LDAP']['LDAP_base'] + ' - exit')
        return False
    return conn


def ldap_user_operation(config, email, conn, headers):
    logger.info(email)
    if (email == config['SSC']['API_email']):
        logger.info(' - it is API accout, skipped...')
        return True
    try:
        ldap_user = test_ldap_user_exist(conn, config['LDAP']['LDAP_base'], config['LDAP']['LDAP_filter'], email)
    except:
        logger.error(' - ldap error, skipped...')
        return False
    if not ldap_user:
        logger.error(' - ldap error, skipped...')
        return False
    if (ldap_user == 1):
        logger.info(' - email is valid, skipped...')
        return True
    if (ldap_user == ERROR_LDAP_LOCKED) or (ldap_user == ERROR_LDAP_NOT_FOUND):
        if (ldap_user == ERROR_LDAP_LOCKED):logger.warning(email + ' - the user is locked in LDAP')
        if (ldap_user == ERROR_LDAP_NOT_FOUND):logger.warning(email + ' - the user email not found in LDAP')
        logger.info('lets delete the account ')
        if (config['EXEC']['dry_run'] == '0'):
            logger.warning('...deleting ' + email)
            delete_user = delete_user_from_ssc(config, headers, email)
            if delete_user:
                if (config['EMAIL']['allow_SES'] == '1'):ses_send_email(config, 'user '+ email + ' is deleted from SSC')
                logger.warning('done')
            else:
                logger.warning('cannot delete the user')
        else:
            logger.warning(' - dry run, we do nothing')
            if (config['EMAIL']['allow_SES'] == '1'):ses_send_email(config, 'user '+ email + ' should be deleted from SSC - dry run')
    return True


def get_secret(config, secret_name):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=config['AWS']['region_name'],
        endpoint_url=config['AWS']['endpoint_url']
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.error("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logger.error("The request was invalid due to:")
            logger.error(e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logger.error("The request had invalid params:")
            logger.error(e)
        return False
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = False
    return secret


def lambda_handler(event, context):
    config = init_cfg('config.cfg')
    if not config: 
        return ERROR
    conn_to_ldap = test_ldap_open(config)
    if not conn_to_ldap: 
        return ERROR
    ssc_data, headers = connection_to_ssc(config)
    if not ssc_data:
        return ERROR  
    ssc_accounts_total = len(ssc_data['data'])
    logger.info(ssc_accounts_total)
    ssc_check_accounts_count = 0
    for ssc_account_record in ssc_data['data']:
        if ('email' in ssc_account_record):
            if ldap_user_operation(config, ssc_account_record['email'], conn_to_ldap, headers):
                ssc_check_accounts_count +=1
        else:
            logger.error('describe email error')
            logger.error(ssc_account_record)
    logger.warning('SSC total accounts: ' +  str(ssc_accounts_total) + ', checked accounts: ' + str(ssc_check_accounts_count))
    return
