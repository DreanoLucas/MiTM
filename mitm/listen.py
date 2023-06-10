'''Fichier contenant les fonctions permetant de lire les paquettes envoyés dans un réseau'''
import scapy 
from scapy.all import sniff
from scapy.layers.http import HTTPRequest
from datetime import datetime

import sys

def check(paquet:scapy)->None:
    """Procedure affichant les paquets HTTP \n
    paquet: tous les paquets transitant dans le réseau
    """
    if HTTPRequest in paquet:  #Si le paquet contient une requète HTTP
        req = paquet[HTTPRequest]

        print("{} ; {} ; {} ; {}".format(
                            datetime.now(),
                            paquet[0][1].dst,
                            req.Method.decode("utf-8"),
                            req.Path.decode("utf-8"))
        )

def http(ip, nb=120):
    """Affiche les trames http capturées d'une ip spécifique. \n
    ip: IP ciblée 
    nb: Nombre de seconde de capture des trames
    """
    print(f"Lecture des trames http de {ip} durant {nb}s.")
    sniff(prn=check, 
          count=nb, 
          filter='src host {}'.format(ip),
          timeout=nb,
          iface="enp0s3")
    print("Fin de transmission")
    
http(sys.argv[1])