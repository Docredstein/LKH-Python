# Test LKH en vue d'une application à fcQUIC 
Je vais (essayer d') implémenter l'architecture du schéma classique présenté dans : https://users.ece.cmu.edu/~adrian/731-sp04/readings/CGIMNP99.pdf 


## Conception : 
### Serveur
Le serveur maintient l'arbre logique et peut s'adresser aux clients par 2 méthodes : un unicast vers chaque membre (modélisé par une fonction send propre à chaque User) et par l'arbre multicast (modélisé par la fonction sendGroup du LKH)
### Client 
Du côté client, il ne connait pas spécifiquement sa place dans l'arbre et doit juste maintenir un dictionnaire des clés qui lui ont été envoyées.  
Il faut donc séparer id de noeud et id de clé. l'id de noeud peut changer avec les changement topologiques de l'arbre et l'id de clé ne change qu'à la destruction du noeud.
## Paquets
### Changement de clé 
```
+-------------------+--------------+-------------+--------------------------------------+
|                   |              |             |                                      |
|       Flags       | id de la clé |    nonce    | Nouvelle clé chiffré par l'ancienne  |
|       1 byte      |   8 bytes    |   12 bytes  |                                      |
|                   |              |             |                                      |
+-------------------+--------------+-------------+--------------------------------------+
```
