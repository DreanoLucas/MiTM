#!/usr/bin/env python3
from scapy.all import ARP,Ether,sendp, hexdump, sr1 
import time as t
import sys 


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