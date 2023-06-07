# def http(ip,nb):
    
from scapy.all import sniff
from scapy.layers.http import HTTPRequest

def check(p):
    if HTTPRequest in p:  # le paquet contient une requÃªte HTTP
        req = p[HTTPRequest]
        print(
            req.Method.decode("utf-8"),
            req.Path.decode("utf-8"),
            req.Http_Version.decode("utf-8")
        )
sniff(prn=check)