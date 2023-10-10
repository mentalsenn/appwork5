#Packaging for EC2 Ubuntu

from myWAP import fMYWAP
from myNMAP import fMYNMAP
from AzureBLOBScanner import checkBLOBWithoutCreds
from GCPStorageScanner import checkGCPBucketWithoutCreds
from S3Scanner import checkBucketWithoutCreds
from mySSLLABS import *
from datetime import *
from myZAP import *
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
import boto3, tldextract, json, logging
from dns import reversename

logging.basicConfig(filename='wessy.log', level=logging.DEBUG)

def domain_details(domain):
    details = {}
    details['domain'] = domain
    details['ip'] = str(socket.gethostbyname(domain))
    details['reverse_dns'] = str(reversename.from_address(details['ip']))
    return details

def mySubDomainBucket(myDomain):
    results = DNSDumpsterAPI({'verbose': True}).search(myDomain)
    subdomains = [domain_details(myDomain)]
    if len(results) > 0:
        subdomains.extend(results['dns_records']['host'])
    return subdomains

def getVersion(oV):
    endofFramework = oV.find('"')
    myV = "|" + oV[0:endofFramework]
    fVer = oV.find('[') + 2
    feVer = oV.find(']') - 1
    myV += oV[int(fVer):int(feVer)]
    return myV

def getText(vname, vurl):

    myurl = vurl
    myapp = vname
    d = datetime.now()
    mydomain = tldextract.extract(myurl)

    try:
        myscore = 50
        myscore += fCIPHER(vurl)

        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table('tblAppScan')
        holdWAPJSON = fMYWAP(myurl)
        jsonSTR = json.dumps(holdWAPJSON)
        holdMySTR = ''
        wafFlag = False
        azFlag = False
        gcpFlag = False

        ####SERVER Platforms####################################
        if jsonSTR.find('Java Servlet') != -1:
            holdMySTR += '|Java Servlet'
            myscore -= 5
        if jsonSTR.find('IIS') != -1:
            holdMySTR += '|IIS'
            myscore -= 5
        if jsonSTR.find('ASP.NET') != -1:
            holdMySTR += '|ASP.NET'
            myscore -= 5

        ####CSP#################################################
        if jsonSTR.find('Azure') != -1:
            holdMySTR += '|Azure'
            azFlag = True
        if jsonSTR.find('Google web server') != -1:
            holdMySTR += '|GCP'
            gcpFlag = True

        ####WAFs/CDN/LBs########################################
        if jsonSTR.find('Incapsula') != -1:
            holdMySTR += '|Incapsula'
            myscore += 15
            wafFlag = True
        if jsonSTR.find('Cloudflare') != -1:
            holdMySTR += '|Cloudflare'
            myscore += 15
            wafFlag = True
        if jsonSTR.find('Akamai') != -1:
            holdMySTR += '|Akamai'
            myscore += 15
            wafFlag = True
        if jsonSTR.find('Azure CDN') != -1:
            holdMySTR += '|Azure CDN'
            azFlag = True
            myscore += 15
        if jsonSTR.find('PerimeterX') != -1:
            holdMySTR += '|PerimeterX'
            myscore += 15
            wafFlag = True
        if jsonSTR.find('Amazon ALB') != -1:
            holdMySTR += '|Amazon ALB'
            myscore += 15
        if jsonSTR.find('Cloudinary') != -1:
            holdMySTR += '|CloudinaryCDN'
            myscore += 15
        if jsonSTR.find('Auth0') != -1:
            holdMySTR += '|Auth0'
            myscore += 15
        if jsonSTR.find('WAF') != -1:
            holdMySTR += '|WAF'
            myscore += 15
            wafFlag = True
        if jsonSTR.find('reCAPTCHA') != -1:
            holdMySTR += '|reCAPTCHA'
            myscore += 15

        ####JS Frameworks#######################################
        if jsonSTR.find('Node.js') != -1:
            varNode = jsonSTR.find('Node.js')
            holdMySTR += "|NodeJS"
            njs = getVersion(jsonSTR[int(varNode):int(varNode) + 40])
            if str(njs) != "14.15":
                myscore -= 25
        if jsonSTR.find('AngularJS') != -1:
            varAJS = jsonSTR.find('AngularJS')
            holdMySTR += "|AnguarJS"
            ajs = getVersion(jsonSTR[int(varAJS):int(varAJS) + 40])
            if str(ajs) != "1.7.2":
                myscore -= 25
        if jsonSTR.find('React') != -1:
            varRE = jsonSTR.find('React')
            holdMySTR += "|ReactJS"
            rjs = getVersion(jsonSTR[int(varRE):int(varRE) + 40])
            if str(rjs) != "17.0":
                myscore -= 25
        if jsonSTR.find('jQuery') != -1:
            varJQ = jsonSTR.find('jQuery')
            holdMySTR += "|jQuery"
            jqs = getVersion(jsonSTR[int(varJQ):int(varJQ) + 40])
            if str(jqs) != "3.5.1":
                myscore -= 25

        ####Cloud Storage#######################################
        if jsonSTR.find('S3') != -1:
            if checkBucketWithoutCreds(mydomain.domain) == True:
                holdMySTR += '|AWSS3Public'
                myscore -= 35
            myAWSList = mySubDomainBucket(mydomain.domain +'.'+ mydomain.suffix)
            for item in myAWSList:
                print(str(item))
        if azFlag == True:
            myAZResult = checkBLOBWithoutCreds(mydomain.domain)
            if myAZResult == True:
                myscore -= 20
                holdMySTR += '|AZBLOB'
            myAZList = mySubDomainBucket(mydomain.domain + '.' + mydomain.suffix)
            for item in myAZList:
                print(str(item))
        if gcpFlag == True:
            myGCPResult = checkGCPBucketWithoutCreds(mydomain.domain)
            if myGCPResult == True:
                myscore -= 35
                holdMySTR += '|GCPBucket'
            myGCPList = mySubDomainBucket(mydomain.domain + '.' + mydomain.suffix)
            for item in myGCPList:
                print(str(item))

        ####NMAP Scanning#######################################
        if wafFlag == False:
            holdNMAPJSON = fMYNMAP(myurl)
            strNMAP = json.dumps(holdNMAPJSON)
            if strNMAP.find('3389'):
                myscore -= 5
                holdMySTR += '|3389Windows'
            elif strNMAP.find('22'):
                myscore -= 5
                holdMySTR += '|22Linux'
            elif strNMAP.find('21'):
                myscore -= 15
                holdMySTR += '|21FTP'
            myscore += fMYZAP(myurl)

        holdMySTR += "----" + str(myscore) + "-----" + str(myurl)
        table.put_item(Item={'AppKey': myapp + '-' + d.strftime("%m-%d-%Y--%H:%M:%S"), 'ScanData': holdMySTR})
        print(holdMySTR)
        return myscore

    except Exception as e:
        print('GetData: ' + str(e))
        logging.DEBUG('GetData: ' + str(e))