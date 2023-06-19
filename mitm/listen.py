#!/usr/bin/env python3
'''Fichier contenant les fonctions permetant de lire les paquettes envoyés dans un réseau'''
import scapy 
from scapy.all import sniff, DNSQR
from scapy.layers.http import HTTPRequest

from datetime import datetime


import json
import sqlite3

from sys import argv

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

    def extract_http(paquet:scapy)->str:
        """Fonction retournants les paquets contenant une requète HTTP \n
        paquet: paquets transitant dans le réseau selon le filtrage du sniff
        """
        if HTTPRequest in paquet:  #Si le paquet contient une requète HTTP
            req = paquet[HTTPRequest]
            resultat = [str(datetime.now()), paquet[0][1].dst, req.Method.decode("utf-8"), req.Path.decode("utf-8")]
            list_sniff.append(resultat)
            return (f"{resultat[0]} ; {resultat[1]} ; {resultat[2]} ; {resultat[3]}")
        
    sniff(prn=extract_http, 
            filter=f'tcp and port 80 and src host {ip}',
            timeout=nb, #Nombre de seconde à capture
            iface="enp0s3")

    create_json_log(list_sniff, "../capture.json")
    create_sql_log(list_sniff, "../capture.db")
    print("Fin de transmission")

def dns(ip, nb=10):
    """Procedure affichant les trames dns capturées d'une ip spécifique. \n
    ip: IP ciblée pour la capture
    nb: Nombre de seconde de capture des trames
    """
    print(f"Lecture des trames dns de {ip} durant {nb}s.")
    noms = [] 

    def extract_dns(paquet:scapy):
        """Fonction retournants les paquets contenant une requète DNS \n
        paquet: paquets transitant dans le réseau selon le filtrage du sniff
        """
        if DNSQR in paquet:
            nom = paquet[DNSQR].qname.decode()
            if nom not in noms:
                noms.append(nom)
                return nom
        
    sniff(filter=f"host {ip} and port 53", 
          prn=extract_dns, 
          timeout=nb,
          iface="enp0s3")

if __name__ == "__main__":
    if argv[1] == "1": 
        http(argv[2])
    elif argv[1] == "2":
        dns(argv[2])
    else: 
        print("1 adresse_ip - http\n2 adresse_ip - dns")
