#!/bin/sh
set -e

# mitigate_docker_2375.sh
# Script simple et idempotent pour appliquer des mesures de mitigation
# contre une API Docker exposée sur le port 2375.
# Usage (exécuter en tant que root):
#   sudo sh mitigate_docker_2375.sh
# Le script :
#  - bloque le port TCP 2375 en IPv4 et IPv6 via iptables
#  - stoppe et supprime les conteneurs qui exposent le port 2375
#  - sauvegarde et nettoie les fichiers locaux docker-entrypoint.sh et docker-compose.yml
#    pour retirer l'écoute TCP et le mapping du port 2375
#  - arrête la stack docker-compose si présente
#  - ajoute une règle auditd pour surveiller /etc/crontabs (si auditctl présent)

# Vérification des privilèges
if [ "$(id -u)" -ne 0 ]; then
  echo "Ce script doit être exécuté en root. Relancer avec sudo." >&2
  exit 1
fi

echo "[1/7] Blocage du port 2375 (IPv4 et IPv6) via iptables..."
# Bloquer IPv4
if command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -p tcp --dport 2375 -j REJECT >/dev/null 2>&1 || \
    iptables -I INPUT -p tcp --dport 2375 -j REJECT
  echo "  -> IPv4: règle iptables ajoutée (ou déjà présente)"
else
  echo "  -> iptables introuvable, skipping IPv4 block"
fi

# Bloquer IPv6
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -C INPUT -p tcp --dport 2375 -j REJECT >/dev/null 2>&1 || \
    ip6tables -I INPUT -p tcp --dport 2375 -j REJECT
  echo "  -> IPv6: règle ip6tables ajoutée (ou déjà présente)"
else
  echo "  -> ip6tables introuvable, skipping IPv6 block"
fi

echo "[2/7] Arrêt et suppression des containers exposant le port 2375..."
if command -v docker >/dev/null 2>&1; then
  PUBLISHED_IDS=$(docker ps --filter "publish=2375" -q || true)
  if [ -n "$PUBLISHED_IDS" ]; then
    for CID in $PUBLISHED_IDS; do
      echo "  -> stop & remove $CID"
      docker rm -f "$CID" || true
    done
  else
    echo "  -> aucun container exposant 2375 trouvé"
  fi
else
  echo "  -> docker introuvable, skipping container cleanup"
fi

# Utility: backup function
backup_file() {
  src="$1"
  if [ -f "$src" ]; then
    bak="${src}.mitigation.bak"
    if [ ! -f "$bak" ]; then
      cp -a "$src" "$bak"
      echo "  -> backup créé: $bak"
    else
      echo "  -> backup déjà présent: $bak"
    fi
  fi
}

echo "[3/7] Sauvegarde et nettoyage de docker-entrypoint.sh (si présent)..."
if [ -f docker-entrypoint.sh ]; then
  backup_file docker-entrypoint.sh
  # retirer l'option --host=tcp://0.0.0.0:2375 si elle existe
  # on fait un remplacement simple et silencieux
  sed -i 's/--host=tcp:\/\/0.0.0.0:2375//g' docker-entrypoint.sh || true
  echo "  -> docker-entrypoint.sh nettoyé (vérifier manuellement si nécessaire)"
else
  echo "  -> docker-entrypoint.sh absent dans le répertoire courant"
fi

echo "[4/7] Sauvegarde et nettoyage de docker-compose.yml (si présent)..."
if [ -f docker-compose.yml ]; then
  backup_file docker-compose.yml
  # supprimer les lignes mappant 2375:2375
  # on supprime uniquement la ligne exacte contenant 2375:2375 pour rester simple
  grep -v "2375:2375" docker-compose.yml > docker-compose.yml.tmp || true
  mv docker-compose.yml.tmp docker-compose.yml
  echo "  -> docker-compose.yml nettoyé (ligne '2375:2375' supprimée si elle existait)"
else
  echo "  -> docker-compose.yml absent dans le répertoire courant"
fi

echo "[5/7] Arrêt de la stack docker-compose (si active)..."
# tenter d'arrêter proprement la stack locale
if command -v docker >/dev/null 2>&1; then
  # on tente docker compose down puis docker-compose down pour compatibilité
  docker compose down --remove-orphans >/dev/null 2>&1 || true
  docker-compose down --remove-orphans >/dev/null 2>&1 || true
  echo "  -> docker compose down tenté (si présent)"
else
  echo "  -> docker introuvable, impossible d'arrêter la stack"
fi

echo "[6/7] Ajouter règle auditd pour surveiller /etc/crontabs (optionnel)..."
if command -v auditctl >/dev/null 2>&1; then
  # création d'une règle d'audit pour écrire/append sur /etc/crontabs
  auditctl -w /etc/crontabs -p wa -k dockerd_cron_mod || true
  echo "  -> règle auditctl ajoutée: /etc/crontabs (clé: dockerd_cron_mod)"
else
  echo "  -> auditctl introuvable, skip audit rule"
fi

echo "[7/7] Mesures terminées. Vérifications recommandées :"
echo "  - vérifier docker-entrypoint.sh.mitigation.bak et docker-compose.yml.mitigation.bak"
echo "  - relancer la stack SEULEMENT après revue: docker compose build && docker compose up -d"
echo "  - pour accès distant légitime, configurer TLS mutual auth pour dockerd au lieu d'exposer 2375"

echo "
Remarques finales :"
echo "  Ce script applique des mesures rapides et sûres pour réduire l'exposition."
echo "  Il crée des backups (*.mitigation.bak) ; vérifie manuellement les modifications avant de redémarrer des services."

echo "Script terminé."
