# -*- coding: utf-8 -*-
#!/usr/bin/env python3
from scapy.all import Ether, ARP, sniff, sendp

def arp_watch(paquet)->None:
    if ARP in paquet and paquet[ARP].op in (1,2):
        mac = paquet[ARP].hwsrc
        ip = paquet[ARP].psrc
        try: 
            if mac != ip_to_mac[ip]:
                print("Empoisonnement ARP detecté pour cette IP : {}".format(ip))
                p  = Ether() / ARP(op=2, hwsrc=ip_to_mac[ip] ,psrc=ip)
                sendp(p)
                print("Empoisonnement ARP déjouer !")
        except:  
            ip_to_mac[ip] = mac

ip_to_mac = {}

def arp():
    p  = Ether() / ARP()
    sendp(p) 
    sniff(filter='arp', prn=arp_watch)

if __name__ == "__main__":
    arp()