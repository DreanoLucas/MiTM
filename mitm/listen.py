#!/usr/bin/env python3
'''Fichier contenant les fonctions permetant de lire les paquettes envoyés dans un réseau'''
import scapy 
from scapy.all import sniff
from scapy.layers.http import HTTPRequest

from datetime import datetime


import json
import sqlite3

import sys

def check(paquet:scapy)->str:
    """Fonction retournants les paquets contenant une requète HTTP \n
    paquet: paquets transitant dans le réseau selon le filtrage du sniff
    """
    if HTTPRequest in paquet:  #Si le paquet contient une requète HTTP
        req = paquet[HTTPRequest]
        return ("{} ; {} ; {} ; {}".format(
                            datetime.now(),
                            paquet[0][1].dst,
                            req.Method.decode("utf-8"),
                            req.Path.decode("utf-8"))
        )

def create_json_log(liste:list, filename:str)->None:
    """Procedure permetant d'ajouter une liste à un fichier JSON \n
    liste: liste d'élément que l'on veut ajouter à un fichier json
    filename: nom du fichier auquel on veut sauvegarder les données
    """ 
    jsonfile = []
    try: 
        f = open(filename, "r")
        jsonfile = json.loads(f.read())
        f.close()
    except:
        pass

    f  = open(filename, "w") 
    for i in liste: 
        dico = {"date": i[0], "ip": i[1], "methode": i[2], "URI":i[3]}
        jsonfile.append(dico)

    f.write(json.dumps(jsonfile, indent=4))
    f.close()

def create_sql_log(liste:list, filename:str):
    """Procedure permetant d'ajouter une liste à un fichier SQL \n
    liste: liste d'élément que l'on veut ajouter à un fichier sqlite
    filename: nom du fichier auquel on veut sauvegarder les données
    """
    connexion = sqlite3.connect(filename)
    cursor = connexion.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS sql_log
                                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                                date TEXT,
                                ip TEXT,
                                methode TEXT, 
                                URI TEXT)""")

    for i in  liste: 
        cursor.execute(f"INSERT INTO sql_log (date, ip, methode, URI) VALUES ('{i[0]}','{i[1]}','{i[2]}','{i[3]}')")
    
    connexion.commit()
    cursor.close
        

def http(ip, nb=10):
    """Procedure affichant les trames http capturées d'une ip spécifique. \n
    ip: IP ciblée pour la capture
    nb: Nombre de seconde de capture des trames
    """
    list_sniff = []
    print(f"Lecture des trames http de {ip} durant {nb}s.")
    sniff(prn=(lambda x: None if check(x) == None #Ne rien afficher si il n'y a pas HTTPRequest
               else list_sniff.append(check(x).split(" ; ")) #Sinon ajouter la réponse a la liste list_sniff
               or check(x)), #et l'affiche en même temps
            filter=f'tcp and port 80 and src host {ip}',
            timeout=nb, #Nombre de seconde à capture
            iface="enp0s3")

    create_json_log(list_sniff, "../capture.json")
    create_sql_log(list_sniff, "../capture.db")
    print("Fin de transmission")

if __name__ == "__main__":
    http(sys.argv[1])