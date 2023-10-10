#Packaging for EC2 Ubuntu

import boto3, logging

logging.basicConfig(filename='wessy.log', level=logging.DEBUG)

def stripDash(vScore):
    if vScore[2:3].isalnum():
        return vScore
    else:
        return vScore[0:2]

def getMetrics():
    try:
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table('tblAppScan')
        response = table.scan()
        items = response.get('Items', [])
        avg = 0
        for item in items:
            hold = str(item['ScanData'])
            myTok = hold.split('|')
            outter = len(myTok)
            avg += int(myTok(outter))
        median = round(avg/len(items),2)
        return median
    except Exception as e:
        print(str(e))
        logging.DEBUG('Metrics error: ' + str(e))