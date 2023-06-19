import sys
from mitm import atk, listen, detect

if sys.argv[1] == "arp":
    ipa = input("adresse1 : ")
    ipb = input("adresse2 : ")
    
    atk.arp(ipa, ipb)
elif sys.argv[1] == "http":
    ip = input("adresse : ")
    listen.http(ip)
elif sys.argv[1] == "dns":
    ip = input("adresse : ")
    listen.dns(ip)
elif sys.argv[1] == "detect_arp":
    detect.arp()
else: 
    print("Ouais force utilise une option valide.")
