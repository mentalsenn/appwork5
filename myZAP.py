#Packaging for EC2 Ubuntu

from zapv2 import ZAPv2
import logging, time

logging.basicConfig(filename='wessy.log', level=logging.DEBUG)

def fMYZAP(vURL):

    try:
        zapScore = 0

        #API Key
        f = open("pwessy.txt", "r")
        apikey = f.readline()
        print(apikey)

        localProxy = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        zap = ZAPv2(proxies=localProxy, apikey=apikey)
        zap.urlopen(vURL)
        zap.spider.scan(url=vURL, apikey=apikey)
        while (int(zap.spider.status()) < 100):
            time.sleep(20)
        response = zap.core.alerts()
        for item in response:
            holdSTR = str(item)
            if(holdSTR.find('''risk': 'High''') > 1):
                zapScore -= 10
            elif(holdSTR.find('''risk': 'Medium''') > 1):
                zapScore -= 5
        return zapScore
    except Exception as e:
        print('Zap error ' + str(e))
        logging.DEBUG('Zap error ' + str(e))