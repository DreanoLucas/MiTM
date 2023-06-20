# **Developpement d'attaque MiTM et de sécurisation du réseau**

## Instalation du paquet
Pour installer le paquet vous pouvez le faire directement en ligne sur le site de Github. 

![image](https://github.com/DreanoLucas/SAE24/assets/118349600/b27363cd-a2c3-4032-b0dd-ad47d502b3c1)

Ou si vous avez git d’installer sur votre machine utiliser simplement la commande : 
**git clone https://github.com/DreanoLucas/SAE24.git** 


## Initialisation du paquet 
Le module setuptools permet d'installer des paquets Python plus facilement en s'occupant de toutes les dépendances et de leur installation. Une fois que setuptools est installé, vous pouvez utiliser la commande python3 **setup.py install --user** pour installer le paquet « mitm ».

Ensuite vous pourrez utiliser les fonctions du paquet. Avec la fonction help vous trouverez les d’information sur des fonctions ou fichiers du paquet. Par exemple si vous voulez savoir comment utiliser le fichier « atk.py » vous devez aller dans un IDE Python et faire les commandes suivantes : 

![image](https://github.com/DreanoLucas/SAE24/assets/118349600/18e20627-c5a3-4d29-b3b8-a0dfc9e6de45)

![image](https://github.com/DreanoLucas/SAE24/assets/118349600/0933faf5-490c-49a2-a60c-4927592f95e8)


## MITM | Fichier mitm/atk.py

Une attaque Man in The Middle est une cyberattaque ou l'attaquant va envoyer des informations erronées pour usurper l’identité d’un appareil sur le réseau local. De cette manière, l'attaquant se place entre les victimes, c’est-à-dire qu’il peut intercepter le trafic, l’écouter et modifier les données échangées entre les utilisateurs. Concrètement si la victime A veut envoyer un message à la victime B, l’attaquant récupère le message et peut en faire ce qu’il veut avant de le renvoyer vers la victime B en l’état ou altéré. Le nom de cette attaque vient du protocole utilisé pour envoyer les fausses informations. 
Dans notre cas nous aurons l’ordinateur d’un utilisateur du réseau comme victime A et comme victime B un serveur web. 

![image](https://github.com/DreanoLucas/SAE24/assets/118349600/761cf3cd-0274-4287-8ffb-f3dde71db9cf)
 
Lors de l’attaque Man in The Middle l’attaquant pourra donc intercepter des données sensibles envoyer par la victime au serveur web comme des mots de passes et identifiants de connexion. 

![image](https://github.com/DreanoLucas/SAE24/assets/118349600/eb8e348f-1129-4c3b-a4aa-741c14c80748)

On peut par exemple récupérer un mot de passe saisie dans un formulaire grâce à ce type d’attaque : 

![image](https://github.com/DreanoLucas/SAE24/assets/118349600/97017279-e08c-45bc-9fce-a2a635e06bf1)

![image](https://github.com/DreanoLucas/SAE24/assets/118349600/e74d05bb-4337-46f5-aa03-5ba8486dd023)

### ARP 
Nous allons appliquer chacune des fonctions expliquées précédemment à un cas concret. Nous avons l’attaquant, le client et le serveur. Le client aura l’adresse IP 192.168.56.1 et le serveur 192.168.56.106. 
Nous utilisons donc notre script « script.py » qui permet d’utiliser les fonctions avec des arguments rentrées en option.  Nous commençons donc par l’utilisation de l’empoisonnement arp entre le client et le serveur, alors on envoie des paquets continuellement aux deux.  

![image](https://github.com/DreanoLucas/SAE24/assets/49568908/b625f15e-44e8-4176-a0a8-601eecf2f75e)

### DHCP 
Pour la fonction d’empoisonnement DHCP il suffit de lancer la fonction DHCP dans le fichier atk.py sans aucune entrée. On écoute le trafic, et lorsque l’on recoit une trame DHCP avec comme option discover nous y répondons avec une offer :

![image](https://github.com/DreanoLucas/SAE24/assets/49568908/488a44a4-5b20-4862-91ce-3cf915067654)

## Ecoute du réseau | Fichier mitm/listen.py

### HTTP
Nous pouvons en parallèle sur un deuxième terminal écouter le client avec la fonction http nous obtiendrons alors pendant 10 secondes par défaut ou le temps rentré en option. Une lecture de toutes les requêtes http effectuées par le client vers le serveur est alors faite et nous pouvons les observées ici. 

![image](https://github.com/DreanoLucas/SAE24/assets/49568908/b6f03e6c-f002-4d23-bc6e-bee62bfc7c94)

### SAUVEGARDE HTTP
Nous pouvons observer ces mêmes résultat dans les fichiers capture.json et capture.db comme expliquer dans leurs parties respectives.

![image](https://github.com/DreanoLucas/SAE24/assets/49568908/ab412cc4-6817-4714-a121-7bafbb371177)

![image](https://github.com/DreanoLucas/SAE24/assets/49568908/2c11f4bf-7b4f-4aa0-bed4-17102af2a036)

### DNS
Nous pourrons maintenant utiliser l’écoute du trafic DNS qui nous donnera les noms de domaine demandé par le client avec la commande host 

![image](https://github.com/DreanoLucas/SAE24/assets/49568908/f44b48f2-d1c4-4d3f-88e6-8b4582863b98)

Notre client étant sur Windows ici nous avons inversé client et serveur pour cette étape. Avec la fonction DNS nous pourrons donc observer l’adresse demandée par le client : 

![image](https://github.com/DreanoLucas/SAE24/assets/49568908/e7fda5d5-c30a-4629-b768-7e06a55b5386)

## Détection des attaques | Fichier mitm/detect.py

### ARP
Enfin pour la detection d’empoisonnement ARP nous utiliserons la fonction arp() qui construira une table ARP dans un dictionnaire, alors lorsque une sera attribue a une nouvelle adresse mac nous serons prévenu d’un potentiel empoisonnement ARP.

![image](https://github.com/DreanoLucas/SAE24/assets/118349600/acbe075d-64eb-4bc1-9405-da47ab396a84)

