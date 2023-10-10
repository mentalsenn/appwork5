#Packaging for EC2 Ubuntu

import requests, logging, boto3, base64
logging.basicConfig(filename='wessy.log', level=logging.DEBUG)

def fMYWAP(appurl):
    try:
        apiKEY = 'Wappalyzer_API'
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager', region_name='us-east-1')
        get_secret_value_response = client.get_secret_value(SecretId=apiKEY)
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        url = "https://api.wappalyzer.com/crawl/v2/?urls="+appurl+"&recursive=false"
        headerInfo = {'content-type': 'application/json' }
        response = requests.get(url, headers=headerInfo, data=secret)
        if response.status_code==200:
            return response.json()
    except Exception as e:
        print('WAP error: ' + str(e))
        logging.DEBUG('WAP error: ' + str(e))