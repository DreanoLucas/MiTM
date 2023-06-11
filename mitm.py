import sys
from mitm import atk, listen, detect

if sys.argv[1] == "arp1":
    ipa = input("adresse1 : ")
    ipb = input("adresse2 : ")
    
    atk.arp(ipa, ipb)
elif sys.argv[1] == "http":
    ip = input("adresse : ")
    listen.http(ip)
elif sys.argv[1] == "arp2":
    detect.arp()
else: 
    print("Ouais force utilise une option valide.")