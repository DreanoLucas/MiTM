'''Fichier contenant les fonctions permetant de lire les paquettes envoyés dans un réseau'''
import scapy 
from scapy.all import sniff
from scapy.layers.http import HTTPRequest
from datetime import datetime

import sys
import json

def check(paquet:scapy)->str:
    """Procedure affichant les paquets HTTP \n
    paquet: tous les paquets transitant dans le réseau
    """
    if HTTPRequest in paquet:  #Si le paquet contient une requète HTTP
        req = paquet[HTTPRequest]
        return ("{} ; {} ; {} ; {}".format(
                            datetime.now(),
                            paquet[0][1].dst,
                            req.Method.decode("utf-8"),
                            req.Path.decode("utf-8"))
        )

def create_json_log(list_sniff:list)->None:
    """ 
    """ 
    jsonfile = []
    try: 
        f = open("../capture.json", "r")
        jsonfile = json.loads(f.read())
        f.close()
    except:
        pass

    f  = open("../capture.json", "w") 
    for i in list_sniff: 
        dico = {"date": i[0], "ip": i[1], "methode": i[2], "URI":i[3]}
        jsonfile.append(dico)

    f.write(json.dumps(jsonfile, indent=4))
    f.close()

def http(ip, nb=10):
    """Affiche les trames http capturées d'une ip spécifique. \n
    ip: IP ciblée 
    nb: Nombre de seconde de capture des trames
    """
    list_sniff = []
    print(f"Lecture des trames http de {ip} durant {nb}s.")
    sniff(prn=(lambda x: None if check(x) == None #Ne rien afficher si il n'y a pas HTTPRequest
               else list_sniff.append(check(x).split(" ; ")) #Sinon ajouter la réponse a la liste list_sniff
               or check(x)), #et l'affiche en même temps
            store=True, 
            count=nb, 
            filter='tcp and port 80 and src host {}'.format(ip),
            timeout=nb,
            iface="enp0s3")

    create_json_log(list_sniff)
    print("Fin de transmission")
    
http(sys.argv[1])