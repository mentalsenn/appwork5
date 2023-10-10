#Packaging for EC2 Ubuntu

import tldextract, socket, ssl, datetime, logging, requests, OpenSSL
from datetime import date
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from requests.packages.urllib3.util import ssl_

logging.basicConfig(filename='wessy.log', level=logging.DEBUG)
global certscore

CIPHERS = 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:AES256-SHA'

def fCIPHER(vURL):
    certscore = 0
    try:
        #Cert expiration
        holdME = tldextract.extract(vURL)
        be = holdME.domain + '.' + holdME.suffix
        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
        today = date.today()
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=be, )
        conn.connect((be, 443))
        ssl_info = conn.getpeercert()
        dDate = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
        myDate = dDate.strftime('%Y-%m-%d')
        if str(today) >= str(myDate):
            certscore -= 10

        #Cipher check
        holdCIPHERS = str(conn.shared_ciphers())
        if holdCIPHERS.find('TLSv1.1') >= 1:
            certscore -= 15
        if holdCIPHERS.find('TLSv1.0') >= 1:
            certscore -= 15
        if holdCIPHERS.find('SSL') >= 1:
            certscore -= 15
        if holdCIPHERS.find('SHA-1') >= 1:
            certscore -= 15
        if holdCIPHERS.find('RC') >= 1:
            certscore -= 20
        if holdCIPHERS.find('DES') >= 1:
            certscore -= 20
        if holdCIPHERS.find('3DES') >= 1:
            certscore -= 20
        if holdCIPHERS.find('IDEA') >= 1:
            certscore -= 20

        #certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, ssl_info)
        #public_key = certificate.get_pubkey()
        #key_length = public_key.bits()
        #if int(key_length) > 2048:
          #  certscore -= 20

        return certscore

    except Exception as e:
        print('CIPHER scan error: ' + str(e))
        logging.DEBUG('CIPHER scan error: ' + str(e))