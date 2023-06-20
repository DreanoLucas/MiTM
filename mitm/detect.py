# -*- coding: utf-8 -*-
#!/usr/bin/env python3
import scapy
from scapy.all import Ether, ARP, sniff, srp, sendp

def arp_table(targets_ip:str)->dict:
    """Fonction permetant de crée la table ARP d'un réseau.
    targets_ip: IP du réseaux du quel on veut la table ARP.
    """
    print("Détection des attaques par arp cache poisoning.")
    packet =Ether(dst="ff:ff:ff:ff:ff:ff") /  ARP(pdst=targets_ip)
    result = srp(packet, timeout=3, verbose=0)[0]

    table = {}
    for received in result[1]:
        table[received.psrc] = received.hwsrc

    return table

def arp():
    """DETECT ARP :\n
    Procedure permetant de détecter et de contrer les attaques d'empoisonment ARP. 
    """
    ip_to_mac = arp_table("192.168.1.0/24")

    def arp_watch(paquet:scapy)->None:
        if ARP in paquet and paquet[ARP].op in (1,2):
            print(ip_to_mac)
            mac_addr = paquet[ARP].hwsrc
            ip_addr = paquet[ARP].psrc
            try:
                if mac_addr != ip_to_mac[ip_addr]:
                    print(
                        f"""Empoisonnement ARP detecté pour cette IP : {ip_addr}
                        Ancienne adresse MAC : {ip_to_mac[ip_addr]}
                        Nouvelle adresse MAC : {mac_addr} (celle du pirate)""")
                    trames  = Ether() / ARP(op=2, hwsrc=ip_to_mac[ip_addr] ,psrc=ip_addr)
                    sendp(trames)
                    print("Empoisonnement ARP déjoué !")
            except:
                ip_to_mac[ip_addr] = mac_addr

    sniff(filter='arp', prn=arp_watch)

if __name__ == "__main__":
    arp()
