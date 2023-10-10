#Packaging for EC2 Ubuntu

import requests, logging

logging.basicConfig(filename='wessy.log', level=logging.DEBUG)

def checkBucketWithoutCreds(bucketName):

    try:
        bucketUrl = 'http://' + bucketName + '.s3.amazonaws.com'
        r = requests.head(bucketUrl)

        if r.status_code == 200:    #No ACLs
            return True
        elif r.status_code == 403:  #ACLs
            return True
        elif r.status_code == 404:  #No bucket
            return False
        else:
            return False
    except Exception as e:
        print("S3 error: " + str(e))
        logging.DEBUG("S3 error: " + str(e))