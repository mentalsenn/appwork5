#Packaging for EC2 Ubuntu

import requests, logging

logging.basicConfig(filename='wessy.log', level=logging.DEBUG)

def checkBLOBWithoutCreds(bucketName):
    try:
        bucketUrl = 'https://' + bucketName + '.blob.core.windows.net/'
        r = requests.head(bucketUrl)
        return False
    except Exception as e:
        print("Azure BLOB funky error")
        logging.DEBUG('Azure funky error')
        return True
