# 🔓 EPFL Camipro Locker Watch

Service autonome léger en Python asynchrone (`httpx` + `asyncio`, ~21 Mo de RAM) conçu pour tourner 24/7 sous Docker ou `systemd` et envoyer une notification push **Telegram** instantanée dès qu'un casier se libère sur le campus de l'EPFL via le portail **MyCamipro v2**.

---

## ✨ Fonctionnalités

- **Interrogation directe de l'API REST EPFL (`axsapi`) :** Vérifie toutes les **45 secondes** les groupes de casiers disponibles par bâtiment, étage et couloir exact (ex. `Centre Est (CE 1 94.9)`) avec lien direct vers le plan interactif **[plan.epfl.ch](https://plan.epfl.ch)**.
- **Renouvellement OAuth2 automatique (Entra ID + PKCE 90 jours) :** Gère à la fois le `refresh_token` horaire et le renouvellement silencieux PKCE (`ESTSAUTHPERSISTENT`) toutes les 24h pour contourner la limite SPA Microsoft (`AADSTS700084`) pendant 90 jours.
- **Zéro doublon :** Persiste l'état des zones dans un fichier local (`lockers_state.json`) et n'envoie une alerte que lorsqu'une zone passe de `0` (occupée) à `> 0` (disponible).
- **Bot Telegram interactif sans latence (Long-Polling) :**
  - `/start` : s'abonner aux alertes de disponibilité (multi-utilisateurs supporté).
  - `/stop` : se désabonner.
  - `/status` : consulter instantanément (< 0.2s) l'état de la session et des casiers libres.
  - `/ests <cookie>` : enregistrer le cookie `ESTSAUTHPERSISTENT` (90 jours) de `login.microsoftonline.com`.
  - `/token <jwt>` & `/refresh <token>` : mettre à jour les jetons à chaud depuis Telegram (réservé à l'administrateur).

---

## 🚀 Installation rapide

### 1. Créer un bot Telegram
1. Discutez avec **[@BotFather](https://t.me/BotFather)** sur Telegram et envoyez `/newbot`.
2. Copiez le jeton HTTP API fourni (`TELEGRAM_BOT_TOKEN`).

### 2. Récupérer vos jetons MyCamipro v2
1. Connectez-vous sur **[https://mycamipro2.epfl.ch/home/equipment/lockers](https://mycamipro2.epfl.ch/home/equipment/lockers)** avec votre compte GASPAR / Microsoft Entra ID.
2. Ouvrez les outils de développement du navigateur (`F12` → onglet **Application** ou **Stockage** → **Local Storage** → `https://mycamipro2.epfl.ch`).
3. Copiez la valeur des deux clés suivantes :
   - `mycamipro.token.entra` → à placer dans `MYCAMIPRO_BEARER_TOKEN`
   - `mycamipro.token.entra.refresh` → à placer dans `MYCAMIPRO_REFRESH_TOKEN`

*(Alternative rapide via l'onglet **Console** de `F12` :)*
```javascript
JSON.stringify({
  bearer: localStorage.getItem('mycamipro.token.entra'),
  refresh: localStorage.getItem('mycamipro.token.entra.refresh')
})
```

### 3. Configurer l'environnement
```bash
git clone <url-du-repo> camipro-watch
cd camipro-watch
cp .env.example .env
chmod 600 .env
touch lockers_state.json
```
Renseignez `TELEGRAM_BOT_TOKEN`, `MYCAMIPRO_BEARER_TOKEN` et `MYCAMIPRO_REFRESH_TOKEN` dans `.env`.

---

## 🐳 Déploiement avec Docker Compose (Recommandé)

```bash
docker compose up -d --build
docker logs -f camipro-watch
```

Ouvrez ensuite votre bot sur Telegram et cliquez sur **Démarrer** (`/start`) :
- Le premier utilisateur qui envoie `/start` devient l'administrateur du bot.
- Toute autre personne envoyant `/start` au bot s'abonne automatiquement aux notifications de casiers disponibles (et peut se désinscrire avec `/stop`).

---

## ⚙️ Déploiement alternatif avec `systemd` (Linux natif)

```bash
sudo mkdir -p /opt/camipro-watch
sudo cp main.py requirements.txt .env lockers_state.json /opt/camipro-watch/
python3 -m venv /opt/camipro-watch/venv
/opt/camipro-watch/venv/bin/pip install -r /opt/camipro-watch/requirements.txt
/opt/camipro-watch/venv/bin/python /opt/camipro-watch/main.py --self-check

sudo chown -R nobody:nogroup /opt/camipro-watch
sudo cp camipro-watch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now camipro-watch.service
sudo journalctl -u camipro-watch -f
```

---

## 📄 Licence

Distribué sous licence [MIT](LICENSE).
