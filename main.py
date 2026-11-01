#!/usr/bin/env python3
"""Surveillance asynchrone 24/7 des casiers EPFL (MyCamipro v2 / AXS API) avec bot Telegram."""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import parse_qs, quote, urlparse

import httpx
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"
load_dotenv(ENV_FILE)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("camipro-watch")

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "45"))
AXS_API_BASE = os.getenv(
    "MYCAMIPRO_LOCKERS_URL",
    "https://camipro-axs-ext.epfl.ch/axsapi/rest/v1",
).rstrip("/")
PORTAL_URL = "https://mycamipro2.epfl.ch/home/equipment/lockers"
ENTRA_TENANT = "f6c2556a-c4fb-4ab1-a2c7-9e220df11c43"
ENTRA_BASE = f"https://login.microsoftonline.com/{ENTRA_TENANT}/oauth2/v2.0"
ENTRA_AUTHORIZE_URL = f"{ENTRA_BASE}/authorize"
ENTRA_TOKEN_URL = f"{ENTRA_BASE}/token"
ENTRA_DEVICE_URL = f"{ENTRA_BASE}/devicecode"
ENTRA_CLIENT_ID = "3fbb9202-de70-4ea9-abd2-a0c15d2262d8"
ENTRA_REDIRECT_URI = "https://mycamipro2.epfl.ch/callback"
ENTRA_SCOPE = "api://3fbb9202-de70-4ea9-abd2-a0c15d2262d8/MyCamipro.Identity email profile openid offline_access"

STATE_FILE = Path(os.getenv("STATE_FILE", str(BASE_DIR / "lockers_state.json")))


class SessionExpiredError(Exception):
    """Levée lorsque le jeton Bearer / cookie MyCamipro est expiré ou rejeté."""


def load_state(path: Path = STATE_FILE) -> Dict[str, int]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("État local illisible (%s), réinitialisation.", exc)
        return {}


def save_state(state: Dict[str, int], path: Path = STATE_FILE) -> None:
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def find_newly_available(old: Dict[str, int], new: Dict[str, int]) -> Dict[str, int]:
    """Retourne uniquement les zones passées de 0 (ou absentes) à > 0."""
    return {
        zone: count
        for zone, count in new.items()
        if count > 0 and old.get(zone, 0) == 0
    }


def parse_chat_ids(raw: str) -> List[str]:
    return [cid.strip() for cid in raw.replace("'", "").replace('"', "").split(",") if cid.strip()]


def save_env_var(key: str, value: str) -> None:
    """Met à jour une variable dans .env en écriture directe (compatible bind-mount Docker)."""
    if not ENV_FILE.exists():
        return
    try:
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
        updated = False
        new_lines = []
        for line in lines:
            if line.startswith(f"{key}="):
                new_lines.append(f'{key}="{value}"')
                updated = True
            else:
                new_lines.append(line)
        if not updated:
            new_lines.append(f'{key}="{value}"')
        ENV_FILE.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    except OSError as exc:
        log.warning("Impossible de sauvegarder %s dans .env : %s", key, exc)


def normalize_ests_cookie(raw: str) -> str:
    raw = raw.strip().strip('"').strip("'")
    if not raw:
        return ""
    if "ESTSAUTHPERSISTENT=" in raw or "ESTSAUTH=" in raw:
        return raw
    return f"ESTSAUTHPERSISTENT={raw}"


async def silent_pkce_login(
    client: httpx.AsyncClient, ests_cookie: str
) -> Tuple[str, str, str]:
    """Renouvelle un jeton SPA expiré (24h, AADSTS700084) via le cookie SSO ESTSAUTHPERSISTENT (90j)."""
    cookie_hdr = normalize_ests_cookie(ests_cookie)
    if not cookie_hdr:
        raise SessionExpiredError("Cookie ESTSAUTHPERSISTENT non configuré")

    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    resp = await client.get(
        ENTRA_AUTHORIZE_URL,
        params={
            "client_id": ENTRA_CLIENT_ID,
            "scope": ENTRA_SCOPE,
            "redirect_uri": ENTRA_REDIRECT_URI,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "none",
        },
        headers={
            "Cookie": cookie_hdr,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0.0.0",
        },
        follow_redirects=False,
        timeout=15.0,
    )

    # Rotation éventuelle de ESTSAUTHPERSISTENT par Microsoft
    for sc in resp.headers.get_list("set-cookie"):
        if sc.startswith("ESTSAUTHPERSISTENT="):
            new_val = sc.split(";", 1)[0].strip()
            if new_val and new_val != "ESTSAUTHPERSISTENT=":
                ests_cookie = new_val
                save_env_var("MYCAMIPRO_ESTS_COOKIE", ests_cookie)

    location = resp.headers.get("location", "")
    parsed = urlparse(location)
    qs = parse_qs(parsed.query) or parse_qs(parsed.fragment)
    if "error" in qs:
        err_desc = qs.get("error_description", [qs["error"][0]])[0]
        raise SessionExpiredError(f"Échec silent login ESTS : {err_desc[:140]}")

    code = (qs.get("code") or [""])[0]
    if not code:
        raise SessionExpiredError("Aucun code OAuth2 renvoyé par silent_pkce_login (cookie ESTSAUTHPERSISTENT expiré)")

    tok_resp = await client.post(
        ENTRA_TOKEN_URL,
        data={
            "client_id": ENTRA_CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": ENTRA_REDIRECT_URI,
            "code_verifier": verifier,
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://mycamipro2.epfl.ch",
        },
        timeout=15.0,
    )
    if tok_resp.status_code != 200:
        raise SessionExpiredError(f"Échec échange code PKCE (HTTP {tok_resp.status_code}): {tok_resp.text[:140]}")

    data = tok_resp.json()
    new_access = data.get("access_token", "")
    new_refresh = data.get("refresh_token", "")
    if not new_access:
        raise SessionExpiredError("Réponse PKCE sans access_token")

    save_env_var("MYCAMIPRO_BEARER_TOKEN", new_access)
    if new_refresh:
        save_env_var("MYCAMIPRO_REFRESH_TOKEN", new_refresh)
    log.info("Session SPA renouvelée pour 24h via ESTSAUTHPERSISTENT (PKCE).")
    return new_access, new_refresh, ests_cookie


async def refresh_entra_token(
    client: httpx.AsyncClient, refresh_token: str, ests_cookie: str = ""
) -> Tuple[str, str, str]:
    """Renouvelle le Bearer token via refresh_token (1h), puis fallback sur ESTSAUTHPERSISTENT si >24h (AADSTS700084)."""
    if refresh_token:
        # Essai sans Origin d'abord (si jeton issu de Device Code 90j), puis avec Origin SPA
        for headers in (
            {"Content-Type": "application/x-www-form-urlencoded"},
            {"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://mycamipro2.epfl.ch"},
        ):
            resp = await client.post(
                ENTRA_TOKEN_URL,
                data={
                    "client_id": ENTRA_CLIENT_ID,
                    "grant_type": "refresh_token",
                    "scope": ENTRA_SCOPE,
                    "refresh_token": refresh_token,
                },
                headers=headers,
                timeout=15.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                new_access = data.get("access_token", "")
                new_refresh = data.get("refresh_token", refresh_token)
                if new_access:
                    save_env_var("MYCAMIPRO_BEARER_TOKEN", new_access)
                    save_env_var("MYCAMIPRO_REFRESH_TOKEN", new_refresh)
                    log.info("Bearer token Entra ID renouvelé via refresh_token.")
                    return new_access, new_refresh, ests_cookie
            if "AADSTS9002327" not in resp.text:
                break

        log.warning("Refresh token expiré (limite SPA 24h AADSTS700084), tentative via ESTSAUTHPERSISTENT...")

    if ests_cookie:
        return await silent_pkce_login(client, ests_cookie)

    raise SessionExpiredError(
        "Le refresh_token SPA a atteint sa limite Microsoft de 24h (AADSTS700084) "
        "et aucun cookie ESTSAUTHPERSISTENT (90j) n'est configuré"
    )


async def fetch_lockers(
    client: httpx.AsyncClient, cookie: str, bearer: str
) -> Dict[str, int]:
    """Interroge camipro-axs-ext.epfl.ch/axsapi/rest/v1/lockergroups (+ /lockers par groupe)."""
    if not bearer:
        raise SessionExpiredError("MYCAMIPRO_BEARER_TOKEN manquant")

    headers = {
        "Authorization": f"Bearer {bearer}",
        "Accept": "application/json",
        "Origin": "https://mycamipro2.epfl.ch",
        "Referer": "https://mycamipro2.epfl.ch/",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0.0.0",
    }
    if cookie:
        headers["Cookie"] = cookie

    resp = await client.get(
        f"{AXS_API_BASE}/lockergroups",
        headers=headers,
        follow_redirects=False,
        timeout=15.0,
    )

    if resp.status_code in (401, 403) or resp.is_redirect:
        raise SessionExpiredError(f"HTTP {resp.status_code} sur /lockergroups")

    content_type = resp.headers.get("content-type", "").lower()
    body = resp.text
    if "text/html" in content_type or "login.microsoftonline.com" in body or "<html" in body[:200].lower():
        raise SessionExpiredError("Redirection vers la mire Microsoft Entra ID (Bearer token expiré)")

    resp.raise_for_status()
    groups = resp.json()
    if not isinstance(groups, list):
        raise SessionExpiredError(f"Format JSON inattendu sur /lockergroups : {body[:120]}")

    result: Dict[str, int] = {}
    for grp in groups:
        grp_id = grp.get("id")
        name = str(grp.get("name") or grp_id or "Inconnu").strip()
        loc = str(grp.get("location") or "").strip()
        label = f"{name} ({loc})" if loc and loc != name else name

        if "availableLockers" in grp or "freeLockers" in grp:
            result[label] = int(grp.get("availableLockers") or grp.get("freeLockers") or 0)
        elif grp_id is not None:
            r_lockers = await client.get(
                f"{AXS_API_BASE}/lockergroups/{grp_id}/lockers",
                headers=headers,
                follow_redirects=False,
                timeout=15.0,
            )
            if r_lockers.status_code == 200 and "application/json" in r_lockers.headers.get("content-type", ""):
                lockers_list = r_lockers.json()
                result[label] = len(lockers_list) if isinstance(lockers_list, list) else 1
            else:
                result[label] = 1
        else:
            result[label] = 1

    return result


async def send_telegram(client: httpx.AsyncClient, token: str, chat_id: str, message: str) -> None:
    if not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        resp = await client.post(
            url,
            json={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        log.error("Échec d'envoi Telegram vers %s : %s", chat_id, exc)


async def broadcast_telegram(
    client: httpx.AsyncClient, token: str, chat_ids: List[str], message: str
) -> None:
    for cid in list(chat_ids):
        await send_telegram(client, token, cid, message)


def format_zone_line(zone: str, count: int) -> str:
    if "(" in zone and zone.endswith(")"):
        loc = zone.rsplit("(", 1)[1][:-1].strip()
        plan_url = f"https://plan.epfl.ch/?q={quote(loc)}"
        return f"• <b>{zone}</b> : {count} libre(s) — <a href='{plan_url}'>Plan EPFL</a>"
    return f"• <b>{zone}</b> : {count} libre(s)"


async def monitor() -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip().strip("'")
    if not token:
        log.critical("TELEGRAM_BOT_TOKEN manquant dans .env")
        sys.exit(1)

    ctx = {
        "chat_ids": parse_chat_ids(os.getenv("TELEGRAM_CHAT_ID", "")),
        "cookie": os.getenv("MYCAMIPRO_SESSION_COOKIE", "").strip(),
        "bearer": os.getenv("MYCAMIPRO_BEARER_TOKEN", "").strip(),
        "refresh": os.getenv("MYCAMIPRO_REFRESH_TOKEN", "").strip(),
        "ests": os.getenv("MYCAMIPRO_ESTS_COOKIE", "").strip(),
        "state": load_state(),
        "session_ok": False,
        "session_alert_sent": False,
    }
    wakeup_event = asyncio.Event()

    async def telegram_loop(client: httpx.AsyncClient) -> None:
        """Boucle long-polling Telegram indépendante : réponse instantanée (<0.2s)."""
        offset = 0
        url = f"https://api.telegram.org/bot{token}/getUpdates"
        while True:
            try:
                resp = await client.get(url, params={"offset": offset, "timeout": 25}, timeout=35.0)
                data = resp.json()
                for upd in data.get("result", []):
                    offset = upd["update_id"] + 1
                    msg = upd.get("message") or {}
                    sender_id = str((msg.get("chat") or {}).get("id") or "")
                    text = (msg.get("text") or "").strip()
                    if not sender_id:
                        continue

                    if text.startswith("/start"):
                        if sender_id not in ctx["chat_ids"]:
                            ctx["chat_ids"].append(sender_id)
                            save_env_var("TELEGRAM_CHAT_ID", ",".join(ctx["chat_ids"]))
                            log.info("Nouvel abonné Telegram enregistré : %s", sender_id)
                        status_line = "🟢 Connectée" if ctx["session_ok"] else "🔴 Expirée"
                        await send_telegram(
                            client,
                            token,
                            sender_id,
                            "✅ <b>Abonnement aux alertes Casiers EPFL activé !</b>\n"
                            f"Session EPFL : <b>{status_line}</b>\n\n"
                            "Commandes :\n"
                            "• <code>/status</code> : état instantané des casiers\n"
                            "• <code>/stop</code> : se désabonner des notifications",
                        )
                    elif text.startswith("/stop"):
                        if sender_id in ctx["chat_ids"]:
                            ctx["chat_ids"].remove(sender_id)
                            save_env_var("TELEGRAM_CHAT_ID", ",".join(ctx["chat_ids"]))
                            log.info("Abonné désinscrit : %s", sender_id)
                        await send_telegram(
                            client,
                            token,
                            sender_id,
                            "🔕 Vous êtes désabonné des alertes. Envoyez <code>/start</code> pour vous réabonner.",
                        )
                    elif text.startswith("/status"):
                        ests_state = "Oui (90j)" if ctx["ests"] else "Non (limite SPA 24h)"
                        status_icon = "🟢 Valide" if ctx["session_ok"] else "🔴 Expirée"
                        st = ctx["state"]
                        summary = (
                            "\n".join(format_zone_line(k, v) for k, v in st.items())
                            if st
                            else "Aucun casier disponible actuellement."
                        )
                        await send_telegram(
                            client,
                            token,
                            sender_id,
                            f"📊 <b>Statut Camipro Watch</b>\n"
                            f"Session : {status_icon}\n"
                            f"Cookie 90j (ESTS) : {ests_state}\n"
                            f"Abonnés : {len(ctx['chat_ids'])}\n\n{summary}",
                        )
                    elif text.startswith(("/token ", "/refresh ", "/ests ")):
                        admin_id = ctx["chat_ids"][0] if ctx["chat_ids"] else sender_id
                        if sender_id != admin_id:
                            await send_telegram(client, token, sender_id, "⛔ Commande réservée à l'administrateur.")
                            continue
                        if text.startswith("/token "):
                            ctx["bearer"] = text[len("/token "):].strip().strip('"').strip("'")
                            save_env_var("MYCAMIPRO_BEARER_TOKEN", ctx["bearer"])
                            msg_ack = "🔄 <b>Bearer token mis à jour !</b> Vérification immédiate..."
                        elif text.startswith("/refresh "):
                            ctx["refresh"] = text[len("/refresh "):].strip().strip('"').strip("'")
                            save_env_var("MYCAMIPRO_REFRESH_TOKEN", ctx["refresh"])
                            msg_ack = "🔄 <b>Refresh token mis à jour !</b> Vérification immédiate..."
                        else:
                            ctx["ests"] = text[len("/ests "):].strip().strip('"').strip("'")
                            save_env_var("MYCAMIPRO_ESTS_COOKIE", ctx["ests"])
                            msg_ack = "🔄 <b>Cookie 90j ESTSAUTHPERSISTENT enregistré !</b> Renouvellement PKCE en cours..."
                        ctx["session_alert_sent"] = False
                        wakeup_event.set()
                        await send_telegram(client, token, sender_id, msg_ack)
            except httpx.HTTPError as exc:
                log.debug("Long-polling Telegram interrompu : %s", exc)
                await asyncio.sleep(2)
            except Exception as exc:
                log.exception("Erreur dans telegram_loop : %s", exc)
                await asyncio.sleep(2)

    async def camipro_loop(client: httpx.AsyncClient) -> None:
        """Boucle de surveillance EPFL stricte toutes les 45s."""
        log.info("Démarrage Camipro Watch sur %s (intervalle=%ds)", AXS_API_BASE, POLL_INTERVAL)
        while True:
            wakeup_event.clear()
            try:
                try:
                    current = await fetch_lockers(client, ctx["cookie"], ctx["bearer"])
                except SessionExpiredError:
                    if ctx["refresh"] or ctx["ests"]:
                        log.info("Renouvellement automatique de la session Entra ID...")
                        ctx["bearer"], ctx["refresh"], ctx["ests"] = await refresh_entra_token(
                            client, ctx["refresh"], ctx["ests"]
                        )
                        current = await fetch_lockers(client, ctx["cookie"], ctx["bearer"])
                    else:
                        raise

                if not ctx["session_ok"]:
                    ctx["session_ok"] = True
                    ctx["session_alert_sent"] = False
                    total_free = sum(current.values())
                    log.info("Session MyCamipro valide (%d groupes, %d libres).", len(current), total_free)
                    if ctx["chat_ids"]:
                        await send_telegram(
                            client,
                            token,
                            ctx["chat_ids"][0],
                            f"✅ <b>Session MyCamipro rétablie !</b> ({len(current)} groupe(s) ouvert(s)).",
                        )

                opened = find_newly_available(ctx["state"], current)
                if opened:
                    lines = [format_zone_line(zone, nb) for zone, nb in opened.items()]
                    msg = (
                        "🔓 <b>Casier(s) EPFL disponible(s) !</b>\n\n"
                        + "\n".join(lines)
                        + f"\n\n👉 <a href='{PORTAL_URL}'>Réserver sur MyCamipro</a>"
                    )
                    log.info("Disponibilité détectée : %s", opened)
                    await broadcast_telegram(client, token, ctx["chat_ids"], msg)

                if current != ctx["state"]:
                    save_state(current)
                    ctx["state"] = current

            except SessionExpiredError as exc:
                ctx["session_ok"] = False
                log.error("Session invalide/expirée : %s", exc)
                if ctx["chat_ids"] and not ctx["session_alert_sent"]:
                    admin_id = ctx["chat_ids"][0]
                    await send_telegram(
                        client,
                        token,
                        admin_id,
                        "⚠️ <b>Alerte MyCamipro : Session expirée</b>\n"
                        f"Raison : <code>{exc}</code>\n\n"
                        "Pour activer le renouvellement automatique <b>90 jours</b> :\n"
                        "1. Ouvrez <code>https://login.microsoftonline.com</code> (en ayant coché <i>Rester connecté</i>).\n"
                        "2. Dans <code>F12</code> → <b>Application</b> → <b>Cookies</b> → <code>https://login.microsoftonline.com</code>, copiez la valeur de <b><code>ESTSAUTHPERSISTENT</code></b>.\n"
                        "3. Envoyez ici : <code>/ests VOTRE_VALEUR</code>",
                    )
                    ctx["session_alert_sent"] = True

            except httpx.RequestError as exc:
                log.warning("Erreur réseau temporaire EPFL : %s", exc)

            except Exception as exc:
                log.exception("Erreur inattendue dans camipro_loop : %s", exc)

            try:
                await asyncio.wait_for(wakeup_event.wait(), timeout=POLL_INTERVAL)
            except asyncio.TimeoutError:
                pass

    async with httpx.AsyncClient(http2=False) as client:
        await asyncio.gather(telegram_loop(client), camipro_loop(client))


def _self_check() -> None:
    diff = find_newly_available({"Centre Est (CE 1 94.9)": 0, "RLC": 1}, {"Centre Est (CE 1 94.9)": 2, "RLC": 3})
    assert diff == {"Centre Est (CE 1 94.9)": 2}
    assert "plan.epfl.ch/?q=CE%201%2094.9" in format_zone_line("Centre Est (CE 1 94.9)", 2)
    assert parse_chat_ids("111, 222 ") == ["111", "222"]
    assert normalize_ests_cookie("0.AXwA...") == "ESTSAUTHPERSISTENT=0.AXwA..."
    print("Self-check OK.")


if __name__ == "__main__":
    if "--self-check" in sys.argv:
        _self_check()
    else:
        try:
            asyncio.run(monitor())
        except KeyboardInterrupt:
            log.info("Arrêt demandé.")
