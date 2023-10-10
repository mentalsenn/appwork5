#Packaging for EC2 Ubuntu

import requests, logging

logging.basicConfig(filename='wessy.log', level=logging.DEBUG)

def checkGCPBucketWithoutCreds(bucketName):
    try:
        response = requests.head('https://www.googleapis.com/storage/v1/b/{}'.format(bucketName))
        if response.status_code == 200:    #No ACLs
            return True
        elif response.status_code == 401:   #No authN provided
            return True
        elif response.status_code == 403:  #ACLs
            return True
        elif response.status_code == 404:  #No bucket
            return False
        else:
            return False
    except Exception as e:
        print("GCP error: " + str(e))
        logging.DEBUG('GCP error')