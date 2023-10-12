#Packaging for EC2 Ubuntu

from urllib.parse import urlparse
import nmap, logging

logging.basicConfig(filename='wessy.log', level=logging.DEBUG)

def fMYNMAP(vURL):
    try:
        nm = nmap.Nmap()
        myres = nm.scan_top_ports(urlparse(vURL).netloc)
        return myres
    except Exception as e:
        print('NMAP error: ' + str(e))
        logging.DEBUG('NMAP error: ' + str(e))