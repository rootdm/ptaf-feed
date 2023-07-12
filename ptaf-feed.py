import logging
import json
import requests
import base64
import signal

from configparser import ConfigParser
from ipaddress import ip_address
from time import time, sleep
from pprint import pprint


CONFIG_FILE = './conf/ptaf-feed.ini'

def main():
    load_config()
    sync_time = cfg.getint('GLOBAL', 'sync_time') * 60
    start_time = time() - sync_time

    while True:

        if time() - start_time > sync_time:
            sync_feeds()
            start_time = time()

        remain = round((sync_time - (time() - start_time))/60)
        logger.debug(f'Next sync: {remain} min')

        sleep(60)

def sync_feeds():
    '''
    Запуск процесса синхронизации фидов PT Feeds -> PTAF
    '''
    logger.info('Starting...')

    headers = {"Content-Type": "application/json"}
    
    access_token = get_token(
        cfg.get('PTAF', 'login'), 
        cfg.get('PTAF', 'password'), 
        headers
    )

    if access_token == False:
        logger.critical('PTAF-Feed Connector is stopped')
        quit()

    headers["Authorization"] = f"Bearer {access_token}"

    list_name = cfg.get('PTAF', 'list_name')
    list_id = get_list_id(list_name, headers)
    logger.info(f'List ID received: {list_id} for {list_name}')

    if not list_id:
        logger.error(f"ERROR: Global List '{list_name}' not found")
        logger.critical('PTAF-Feed Connector is stopped')
        quit()
    
    data = collect_feeds()
    json_data = json.dumps(data)

    with open('./conf/feeds_data.json', 'w') as outfile:
        outfile.write(json_data)

    # with open('json_data.json') as json_file:
        # data = json.load(json_file)

    # pprint(data)

    request_counter = 0
    ip_count = 0
    ip_list = []

    ip_total = len(data['ip'])
    ip_limit = cfg.getint('PTAF', 'limit_per_request')

    for i in range(0, ip_total):
        ip = data['ip'][i]

        ip_list.append(ip)
        ip_count += 1

        if (ip_count >= ip_limit) or (i == ip_total - 1):
            request_counter += 1
            add_ip([list_id], ip_list, cfg.getint('PTAF', 'ip_ttl'), headers)
            
            logger.info(
                f'Added {len(ip_list)} ip addresses to {list_name}, '
                f'request no.: {request_counter}'
            )

            ip_count = 0
            ip_list = []

    return


def collect_feeds():
    '''
    Выгрузка всех фидов из базы
    Отправка на фильтрацию
    '''

    retry = 0
    token = 0

    d = {}
    d['nodeRoles'] = {}
    d['threatTypes'] = []
    d['labels'] = {}
    d['ip'] = []
    d['dup'] = 0
    
    while True:
        result = get_feeds(token, cfg.get('PTFEEDS', 'limit_per_request'))

        if result == False:
            retry += 1
            logger.warning(f'Request error, retry: {retry}')

            if retry == 10:
                logger.critical(f'Feed requests failed! Attempts: {retry}')
                return False
            continue
        elif result == True:
            break
        else:
            retry = 0

        token = result['lastToken']

        logger.info(
            f'Received {len(result["items"])} feed items, last token: {token}'
        )

        ip_count = 0
        for item in result['items']:
            if item['object']['type'] == 'ip':
                ip = item['object'].get('ip')

                if is_valid_ipv4_address(ip):
                    if ip not in d['ip']:
                        d['ip'].append(ip)
                        ip_count += 1
                    else:
                        d['dup'] += 1
                        # logger.debug(f'Duplicated item detected, IP: {ip}')
                else:
                    logger.warning(f'Feed IPv4 "{ip}" validation failed')

                if item['object']['threatType'] not in d['threatTypes']:
                    d['threatTypes'].append(item['object']['threatType'])
                
                for label in item['object']['labels']:
                    d['labels'][label] = d['labels'].get(label, 0) + 1
                
                if item['object'].get('nodeRoles') != None:
                    for role in item['object']['nodeRoles']:
                        d['nodeRoles'][role] = d['nodeRoles'].get(role, 0) + 1
    
        if ip_count > 0:
            logger.info(f'Added {ip_count} IP type feeds'
        )

    logger.info(
        f'Finished. Received {len(d["ip"])} IP feed items, '
        f'duplicated items: { d["dup"] }'
    )

    return d


def is_valid_ipv4_address(address):
    '''
    Проверка значения на валидный формат IPv4
    '''

    try:
        ip = ip_address(address)
        return True
    except ValueError:
        return False


def get_feeds(token=False, limit=False):
    '''
    Запрос фидов по API
    Результат: 
    - False - ошибка выполнения запроса к PT Feeds 
    - True - нет данных (когда значение токена больше, чем количество фидов)
    - Dict - словарь данных с фидами
    '''

    params = {}

    if token:
        params['token'] = token

    if limit:
        params['limit'] = limit

    headers = {"Content-Type": "application/json"}
    response = request_get(
        cfg.get('PTFEEDS', 'api_url'), 
        '/reputationLists', 
        headers, 
        params
    )

    if not response:
        return False

    if response.status_code == 200:
        return (response.json())
    elif response.status_code == 204:
        return True

    return False


def remove_ip(lists, items, headers):
    '''
    Удаление IP-адресов из глобального динамического списка
    (или несколько списков)
    '''

    url = '/config/global_lists/remove_items'
    data = { 'items' : items }

    if type(lists) is list:
        data['global_lists'] = lists

    response = request_post(cfg.get('PTAF', 'api_url'), url, data, headers)

    logger.debug(
        f'Status Code: {response.status_code}, response: { response.json() }'
    )

    if response.status_code == 200 and response.json().get('status') == 'OK':
        return True

    return False

def add_ip(lists, items, ttl, headers):
    '''
    Добавление IP-адресов в глобальный динамический список 
    (или несколько списков)
    '''

    url = '/config/global_lists/add_items'
    data = { 'items' : items, "ttl": ttl }

    if type(lists) is list:
        data['global_lists'] = lists

    response = request_post(cfg.get('PTAF', 'api_url'), url, data, headers)

    logger.debug(
        f'Status Code: {response.status_code}, response: { response.json() }'
    )

    if response.status_code == 200 and response.json().get('status') == 'OK':
        return True

    return False

def get_list_id(name, headers):
    '''
    Получить ID глобального списка по имени списка
    '''

    global_lists = get_global_lists(headers)

    for item in global_lists['items']:
        if name == item['name']:
            return item['id']

    return False


def get_global_lists(headers):
    '''
    Получение перечня глобальных списков
    '''

    response = request_get(
        cfg.get('PTAF', 'api_url'), 
        '/config/global_lists', 
        headers
    )

    if response.status_code == 200:
        return response.json()
    else:
        return False


def get_token(login, password, headers):
    '''
    Авторизация и запрос токена PTAF4
    '''

    data = {"username": login,
            "password": password,
            "fingerprint": "python"}

    logger.info('PTAF - token authentication request')
    response = request_post(
        cfg.get('PTAF', 'api_url'), 
        "/auth/refresh_tokens", 
        data, 
        headers
    )

    if response:
        if (response.status_code == 201):
            token = response.json()['access_token']

            logger.debug(
                f"Access token for {login}: {token[:15]}... "
                f"(Length: {len(token)}b)"
            )
            return(token)

    logger.critical('Get auth token error')
    return False


def request_get(api_url, url, headers, params={}):
    '''
    GET запрос и обработчик ошибок 
    '''

    try:
        response = requests.get(api_url + url,
                                 headers=headers,
                                 params=params,
                                 verify=False,
                                 timeout=5)

        logger.debug(
            f'GET REQUEST: {api_url + url}, '
            f"STATUS CODE: {str(response.status_code)}"
        )

        return response

    except requests.exceptions.HTTPError as errh:
        logger.error(f'HTTP Error: {errh}')

    except requests.exceptions.ConnectionError as errc:
        logger.error(f'Connection Error: {errc}')

    except requests.exceptions.Timeout as errt:
        logger.error(f'Timeout error: {errt}')

    except requests.exceptions.RequestException as err:
        logger.error(f'Request Exception: {err}')

    return False


def request_post(api_url, url, data, headers):
    '''
    POST запрос и обработчик ошибок 
    '''

    try:
        response = requests.post(api_url + url,
                                 data=json.dumps(data),
                                 headers=headers,
                                 verify=False,
                                 timeout=5)

        logger.debug(
            f'POST REQUEST: {api_url + url}, '
            f"STATUS CODE: {str(response.status_code)}"
        )

        return response

    except requests.exceptions.HTTPError as errh:
        logger.error(f'HTTP Error: {errh}')

    except requests.exceptions.ConnectionError as errc:
        logger.error(f'Connection Error: {errc}')

    except requests.exceptions.Timeout as errt:
        logger.error(f'Timeout error: {errt}')

    except requests.exceptions.RequestException as err:
        logger.error(f'Request Exception: {err}')

    return False

def load_config():
    global cfg

    cfg = ConfigParser()
    cfg.read(CONFIG_FILE)

    debug_level = 2
    if cfg.has_option('GLOBAL', 'debug'):
        debug_level = cfg.get('GLOBAL', 'debug')
    
    logger_setup(debug_level)

    if len(cfg.sections()) == 0:
        logger.critical(f"Unable to read the config file {CONFIG_FILE}")
        quit()

    options = {
        'GLOBAL': ['debug'], 
        'PTAF': [ 
            'api_url', 'login', 'password', 'ip_ttl', 
            'list_name', 'limit_per_request'
        ], 
        'PTFEEDS': ['api_url', 'limit_per_request']
        }

    for section in options.keys():
        if section not in cfg.sections():
            logger.critical(
                f"Section '{section}' not found in the config {CONFIG_FILE}"
            )
            quit()
        for option in options[section]:
            if not cfg.has_option(section, option):
                logger.critical(
                    f"Config Error: Option '{option}' not found" 
                    f"in the section '{section}'"
                )
                quit()


def logger_setup(debug_level):
    '''
    Enable logging
    '''
    global logger

    debug_level = int(debug_level)

    levels = {
        7: logging.DEBUG,
        6: logging.INFO,
        4: logging.WARNING,
        3: logging.ERROR,
        2: logging.CRITICAL,
    }

    level = levels.get(debug_level, logging.CRITICAL)

    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=level
    )
    logger = logging.getLogger('PTFeedConnector')

    if debug_level == 0:
        logger.disabled = True


    # if debug_level < 4:
    # Disable InsecureRequestWarning warning message
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def signal_handler(signum, frame):
    logger.info('Stopping PTAF-PTFeed Connector.')
    quit()

if __name__ == "__main__":
    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        main()
    
    except KeyboardInterrupt:
        logger.info('Stopping...')
        quit()
