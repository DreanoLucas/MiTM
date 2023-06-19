'''Script permetant de lancer facilement les fonction principale du paquet mitm \n 
Les arguments utilisables sont:
arp, http, dns, detect_arp. ''' 
import script
from sys import argv 
from mitm import atk, listen, detect


try: 
    if  argv[1] == "arp":
        ipa = input("adresse1 : ")
        ipb = input("adresse2 : ")
        atk.arp(ipa, ipb)   
    elif argv[1] == "http":
        ip = input("adresse : ")
        listen.http(ip)
    elif argv[1] == "dns":
        ip = input("adresse : ")
        listen.dns(ip)
    elif argv[1] == "detect_arp":
        detect.arp()
    raise ValueError
except: 
    help(script)
