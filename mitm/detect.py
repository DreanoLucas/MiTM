# -*- coding: utf-8 -*-
#!/usr/bin/env python3
import scapy
from scapy.all import Ether, ARP, sniff, srp, sendp

def arp_watch(paquet:scapy)->None:
    global ip_to_mac
    if ARP in paquet and paquet[ARP].op in (1,2):
        # print(ip_to_mac)
        mac = paquet[ARP].hwsrc
        ip = paquet[ARP].psrc
        try: 
            if mac != ip_to_mac[ip]:
                print(f"""Empoisonnement ARP detecté pour cette IP : {ip}\nAncienne adresse MAC : {ip_to_mac[ip]}\nNouvelle adresse MAC : {mac} (celle du pirate)""")
                p  = Ether() / ARP(op=2, hwsrc=ip_to_mac[ip] ,psrc=ip)
                sendp(p)
                print("Empoisonnement ARP déjoué !")
        except:  
            ip_to_mac[ip] = mac

def arp_table(target_ip:str)->dict:
    print("Détection des attaques par arp cache poisoning.")
    packet =Ether(dst="ff:ff:ff:ff:ff:ff") /  ARP(pdst=target_ip)
    result = srp(packet, timeout=3, verbose=0)[0]

    arp_table = {}
    for received in result[1]:
        arp_table[received.psrc] = received.hwsrc

    return arp_table

def arp():
    sniff(filter='arp', prn=arp_watch)

ip_to_mac = arp_table("192.168.1.0/24")

if __name__ == "__main__":
    arp()