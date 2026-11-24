import hashlib
import json
import logging
import os
import secrets
import string

import boto3
import pymysql
from botocore.exceptions import ClientError

from conexion import conectar

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
sm = boto3.client('secretsmanager')
ssm = boto3.client('ssm')



def secreto(secret_id, **kwargs):
    response = sm.get_secret_value(SecretId=secret_id, **kwargs)
    return json.loads(response['SecretString'])


def parametro_opcional(name):
    try:
        return ssm.get_parameter(Name=name, WithDecryption=True)['Parameter']['Value']
    except ClientError as error:
        if error.response['Error']['Code'] == 'ParameterNotFound':
            return None
        raise


def nueva_clave():
    alphabet = string.ascii_letters + string.digits + '!@#%_-'
    while True:
        value = ''.join(secrets.choice(alphabet) for _ in range(28))
        if (any(c.islower() for c in value) and any(c.isupper() for c in value)
                and any(c.isdigit() for c in value)
                and any(c in '!@#%_-' for c in value)):
            return value


def rotar_ambiente(connection, admin, ambiente, event_id):
    secret_id = os.environ['APP_SECRET_PREFIX'].rstrip('/') + '/' + ambiente
    prefix = os.environ['PARAMETER_PREFIX'].rstrip('/')
    password_path = f'{prefix}/user_{ambiente}/password'
    pending_path = f'{prefix}/rotation_pending/{ambiente}'
    token = hashlib.sha256(f'{event_id}:{ambiente}'.encode()).hexdigest()
    data = secreto(secret_id)
    if (data['username'] != f'user_{ambiente}' or data['dbname'] != ambiente
            or data['host'] != admin['host']
            or int(data.get('port', 3306)) != int(admin.get('port', 3306))):
        raise ValueError('El secreto no corresponde al ambiente o a la RDS esperada')

    pending = parametro_opcional(pending_path)
    if pending is None:
        try:
            secreto(secret_id, VersionId=token)
        except ClientError as error:
            if error.response['Error']['Code'] != 'ResourceNotFoundException':
                raise
        else:
            return {'ambiente': ambiente, 'estado': 'evento_ya_completado'}

        pending = json.dumps({'token': token, 'password': nueva_clave()})
        # Guardar antes de modificar MySQL: una siguiente invocacion puede reanudar.
        ssm.put_parameter(Name=pending_path, Value=pending,
                          Type='SecureString', Overwrite=False)

    state = json.loads(pending)
    candidate = dict(data, password=state['password'])
    check = None
    try:
        check = conectar(candidate, ambiente)
    except pymysql.err.OperationalError as error:
        if error.args[0] != 1045:  
            raise
        with connection.cursor() as cursor:
            cursor.execute('ALTER USER %s@%s IDENTIFIED BY %s', (
                data['username'], os.environ.get('MYSQL_ACCOUNT_HOST', '%'),
                state['password'],
            ))
        check = conectar(candidate, ambiente)
    try:
        with check.cursor() as cursor:
            cursor.execute('SELECT 1')
            cursor.fetchone()
    finally:
        if check is not None:
            check.close()

    updated = ssm.put_parameter(Name=password_path, Value=state['password'],
                                Type='SecureString', Overwrite=True)
    saved = sm.put_secret_value(
        SecretId=secret_id,
        ClientRequestToken=state['token'],
        SecretString=json.dumps(candidate, sort_keys=True),
    )
    ssm.delete_parameter(Name=pending_path)
    result = {'ambiente': ambiente, 'usuario': data['username'], 'estado': 'rotado',
              'ssm_version': updated['Version'], 'secret_version': saved['VersionId']}
    log.info(json.dumps(result))
    return result


def lambda_handler(event, context):
    connection = None
    try:
        admin = secreto(os.environ['ADMIN_SECRET_ID'])
        connection = conectar(admin)
        with connection.cursor() as cursor:
            cursor.execute('SELECT GET_LOCK(%s, 0)', ('alumnos_rotation',))
            if cursor.fetchone()[0] != 1:
                return {'estado': 'otra_rotacion_en_curso'}
        event_id = event.get('id') or context.aws_request_id
        return {'resultados': [rotar_ambiente(connection, admin, env, event_id)
                              for env in AMBIENTES]}
    except Exception as error:
        code = (error.response['Error']['Code'] if isinstance(error, ClientError)
                else error.args[0] if error.args and isinstance(error.args[0], int)
                else type(error).__name__)
        log.error('Rotacion incompleta: %s; revisar permisos, red y parametros pendientes', code)
        raise RuntimeError('Rotacion incompleta. Corregir causa y reintentar; no borrar pendientes.') from None
    finally:
        if connection is not None:
            connection.close()
