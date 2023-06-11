# -*- coding: utf-8 -*-
#!/usr/bin/env python3
from scapy.all import Ether, ARP, sniff, sendp, srp

ip_to_mac = {}

def arp_watch(paquet)->None:
    if ARP in paquet and paquet[ARP].op in (1,2):
        mac = paquet[ARP].hwsrc
        ip = paquet[ARP].psrc
        try: 
            if mac != ip_to_mac[ip]:
                print("Empoisonnement ARP detecté pour cette IP : {}".format(ip))
                p  = Ether() / ARP(op=2, hwsrc=ip_to_mac[ip] ,psrc=ip)
                sendp(p)
                print("Empoisonnement ARP déjoué !")
        except:  
            ip_to_mac[ip] = mac


def arp_table(target_ip):
    packet =Ether(dst="ff:ff:ff:ff:ff:ff") /  ARP(pdst=target_ip)
    result = srp(packet, timeout=3, verbose=0)[0]

    arp_table = {}
    for received in result[1]:
        arp_table[received.psrc] = received.hwsrc

    return arp_table

def arp():
    ip_to_mac = arp_table("192.168.1.0/24")
    print(ip_to_mac)
    sniff(filter='arp', prn=arp_watch)

if __name__ == "__main__":
    arp()