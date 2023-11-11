import configparser
import logging
import os
import socket
from logging.handlers import RotatingFileHandler
import uuid
import click
import globus_sdk
from fastapi import FastAPI, Security, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
import uvicorn

from globus_sdk import (TransferAPIError)

app = FastAPI(title="PRIDE Globus WS",
              description="PRIDE Globus WS",
              version="0.0.1",
              contact={
                  "name": "PRIDE Team",
                  "url": "https://www.ebi.ac.uk/pride/",
                  "email": "pride-support@ebi.ac.uk",
              },
              license_info={
                  "name": "Apache 2.0",
                  "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
              }, )

api_key_header = APIKeyHeader(name="x-api-key")


def get_api_key(key: str = Security(api_key_header)) -> str:
    if key == API_KEY:
        return key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )


app_logger = logging.getLogger("uvicorn")  # unify the uvicorn logging with fast-api logging
CLIENT_ID = None
CLIENT_SECRET = None
API_KEY = None
COLLECTION_END_POINT: uuid.UUID = None
NOTIFY_EMAIL_MSG = None


@app.get("/")
def read_root():
    return JSONResponse(content=app.openapi())


@app.get("/docs")
def read_docs():
    return JSONResponse(content=app.openapi())


@app.put("/log/{level}")
def change_log_level(level):
    level_upper = str(level).upper()
    logging.getLogger("uvicorn.error").setLevel(level_upper)
    logging.getLogger("uvicorn.access").setLevel(level_upper)
    logging.getLogger("uvicorn.asgi").setLevel(level_upper)
    app_logger.setLevel(level_upper)


@app.get("/health")
def read_docs():
    return 'alive'


@app.post("/create-shared-dir")
def create_shared_dir(globus_username: str, dir_name: str = None, api_key: str = Security(get_api_key)):
    app_client, authorizer = get_confidential_app_client_and_authorizer(CLIENT_ID, CLIENT_SECRET)
    tc = globus_sdk.TransferClient(authorizer=authorizer)

    ids_resp = app_client.get_identities(usernames=globus_username)

    ids = ids_resp['identities']
    if len(ids) == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=globus_username + " is not registered with Globus",
        )

    id_json = ids[0]

    if dir_name is None:
        dir_prefix = globus_username
        if "@" in globus_username:
            i = globus_username.index("@")
            dir_prefix = globus_username[0:i]
        dir_name = '/' + dir_prefix + '_' + str(uuid.uuid4()) + '/'

    try:
        ddir = tc.operation_mkdir(endpoint_id=COLLECTION_END_POINT, path=dir_name)
    except TransferAPIError as e:
        if e.code == 'ExternalError.MkdirFailed.Exists':
            raise HTTPException(status_code=409, detail="Dir already exists: " + dir_name)
        else:
            raise HTTPException(status_code=e.http_status, detail=e.message)

    if not dir_name.endswith('/'):
        dir_name = dir_name + '/'
    if not dir_name.startswith('/'):
        dir_name = '/' + dir_name

    rule_data = {
        "DATA_TYPE": "access",
        "principal_type": "identity",
        "principal": id_json['id'],
        "path": dir_name,
        "permissions": "rw",
        "notify_email": id_json['email'],
        "notify_message": NOTIFY_EMAIL_MSG
    }

    acl_add = tc.add_endpoint_acl_rule(COLLECTION_END_POINT, rule_data)
    app_logger.info("Created dir : " + dir_name + " and shared with " + globus_username)
    return dir_name


@app.get("/list-dir")
def list_dir(path: str, api_key: str = Security(get_api_key)):
    app_client, authorizer = get_confidential_app_client_and_authorizer(CLIENT_ID, CLIENT_SECRET)
    tc = globus_sdk.TransferClient(authorizer=authorizer)
    try:
        ls_out = tc.operation_ls(endpoint_id=COLLECTION_END_POINT, path=path)
    except TransferAPIError as e:
        app_logger.error(e)
        print(e.message)
        if e.http_status == 404:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Directory " + path + " not found",
            )
        else:
            raise HTTPException(
                status_code=e.http_status,
                detail=e.message,
            )

    # print(ls_out['DATA'])
    # app_logger.info(ls_out['DATA'])
    return ls_out['DATA']


@app.get("/get-shared-dirs")
def get_shared_dirs(api_key: str = Security(get_api_key)):
    app_client, authorizer = get_confidential_app_client_and_authorizer(CLIENT_ID, CLIENT_SECRET)
    tc = globus_sdk.TransferClient(authorizer=authorizer)
    try:
        acl_list = tc.endpoint_acl_list(COLLECTION_END_POINT)
    except TransferAPIError as e:
        app_logger.error(e)
        print(e.message)
        raise HTTPException(
            status_code=e.http_status,
            detail=e.message,
        )

    # print(acl_list['DATA'])
    return acl_list['DATA']


@app.delete("/unshare-dir")
def unshare_dir(path: str, api_key: str = Security(get_api_key)):
    app_client, authorizer = get_confidential_app_client_and_authorizer(CLIENT_ID, CLIENT_SECRET)
    tc = globus_sdk.TransferClient(authorizer=authorizer)
    dirs = get_shared_dirs()
    # print(dirs)
    if not path.endswith('/'):
        path = path + '/'
    if not path.startswith('/'):
        path = '/' + path
    for i in dirs:
        if i['path'] == path:
            tc.delete_endpoint_acl_rule(COLLECTION_END_POINT, i['id'])
            app_logger.info("Successfully unshared dir : " + path)


@app.delete("/delete-dir")
def delete_dir(path: str, api_key: str = Security(get_api_key)):
    app_client, authorizer = get_confidential_app_client_and_authorizer(CLIENT_ID, CLIENT_SECRET)
    tc = globus_sdk.TransferClient(authorizer=authorizer)
    # just to check if the dir exists or not. If it doesn't exist, the list_dir() function returns HTTP error
    ls = list_dir(path)
    unshare_dir(path)
    ddata = globus_sdk.DeleteData(tc, COLLECTION_END_POINT, recursive=True)
    ddata.add_item(path)
    task = tc.submit_delete(ddata)
    app_logger.info('delete_dir {} , task_id: {}'.format(path, task['task_id']))
    tc.task_wait(task['task_id'])
    app_logger.info('Successfully deleted_dir {} , task_id: {}'.format(path, task['task_id']))


def get_config(file):
    """
    This method read the default configuration file config.ini in the same path of the pipeline execution
    :return:
    """
    config = configparser.ConfigParser()
    config.read(file)
    return config


@click.command()
@click.option('--config-file', '-a', type=click.Path(), default='config.ini')
@click.option('--config-profile', '-c', help="This option allow to select a config profile", default='TEST')
def main(config_file, config_profile):
    global CLIENT_ID, CLIENT_SECRET, API_KEY, COLLECTION_END_POINT, NOTIFY_EMAIL_MSG, app_logger
    config = get_config(config_file)
    port = config[config_profile]['PORT']
    CLIENT_ID = config[config_profile]['CLIENT_ID']
    CLIENT_SECRET = config[config_profile]['CLIENT_SECRET']
    API_KEY = config[config_profile]['API_KEY']
    COLLECTION_END_POINT = uuid.UUID(config[config_profile]['COLLECTION_END_POINT'])
    NOTIFY_EMAIL_MSG = config[config_profile]['NOTIFY_EMAIL_MSG']
    LOG_LEVEL = config[config_profile]['LOG_LEVEL']

    logging.getLogger("uvicorn.access").addFilter(NoHealthAccessLogFilter())

    logs_path = config[config_profile]['LOGS_PATH']
    if not logs_path.endswith('/'):
        logs_path = logs_path + '/'
    log_filename = logs_path + socket.gethostname() + '.log'
    log_max_size = config[config_profile]['LOG_MAX_SIZE']  # 1024 * 1024  # 1 MB
    log_backup_count = config[config_profile]['LOG_BACKUP_COUNT']
    log_format = '%(asctime)s.%(msecs)03d %(levelname)s %(message)s'

    if '/' in log_filename:
        i = log_filename.rindex("/")  # get the last index of '/' ex: /a1/b2/c3/asd.log
        log_path = log_filename[0:i]
        if not (os.path.exists(log_path) and os.path.isdir(log_path)):
            os.makedirs(log_path)

    # Create a RotatingFileHandler
    file_handler = RotatingFileHandler(log_filename, maxBytes=int(log_max_size), backupCount=int(log_backup_count))
    file_handler.setFormatter(logging.Formatter(log_format, datefmt='%Y-%m-%d %H:%M:%S'))
    app_logger.setLevel(LOG_LEVEL)
    app_logger.addHandler(file_handler)

    # https://github.com/tiangolo/fastapi/discussions/7457#discussioncomment-5141108
    # unify the uvicorn logging with fast-api logging
    uvicorn.run(app, host="0.0.0.0", port=int(port), log_config=None)


class NoHealthAccessLogFilter(logging.Filter):
    def filter(self, record):
        message = record.getMessage()
        if "GET /health" in message:
            return False
        else:
            return True


def get_confidential_app_client_and_authorizer(client_id, client_secret):
    client = globus_sdk.ConfidentialAppAuthClient(
        client_id=client_id,
        client_secret=client_secret)
    token_response = client.oauth2_client_credentials_tokens()
    tokens = token_response.by_resource_server
    transfer_tokens = tokens['transfer.api.globus.org']
    transfer_access_token = transfer_tokens['access_token']

    return client, globus_sdk.AccessTokenAuthorizer(transfer_access_token)


if __name__ == "__main__":
    main()
