from flask import Flask, request, jsonify
from flask_cors import CORS   
import os, requests, socket, ssl, tldextract     
from bs4 import BeautifulSoup 
import ssl, socket, hashlib
from datetime import datetime
import re
import json


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  

API_URL = "https://api.mistral.ai/v1/chat/completions"
API_KEY = "weJ4ql0E9sx3VJYdooeE2TUDM8sfjMHj"

@app.route("/analyze", methods=["POST", "OPTIONS"])  
def analyze_mail():
    # gestion du pré-vol (préflight)
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    data = request.get_json(force=True)
    subject = data.get("subject", "")
    sender = data.get("from", "")
    text = data.get("text", "")
    links = [l["href"] for l in data.get("links", [])]


    def duckduckgo_search(query):

        url = "https://html.duckduckgo.com/html/?q=" + query.replace(" ", "+")
        headers = {"User-Agent": "Mozilla/5.0"}
        try:
            r = requests.get(url, timeout=5, headers=headers)
            if r.status_code != 200:
                return []
            soup = BeautifulSoup(r.text, "html.parser")
            results = []
            for a in soup.select("a.result__a"):
                href = a.get("href")
                title = a.text.strip()
                if href:
                    results.append({"title": title, "url": href})
            return results[:3]
        except Exception as e:
            print("⚠️ Erreur DuckDuckGo :", e)
            return []

    def check_mentions_legales(url):
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            r = requests.get(url, timeout=5, headers=headers, allow_redirects=True)
            if r.status_code != 200:
                return {"exists": False, "details": None}
            soup = BeautifulSoup(r.text, "html.parser")
            text = soup.get_text(" ", strip=True).lower()

            keywords = ["mention légale", "mentions légales", "informations légales",
                        "legal notice", "terms of service", "terms and conditions", "privacy policy", "conditions générales", "conditions", "conditions d'utilisation", "Informations légales", "Informations", "Légales", "Terms", "Conditions"]
            mention_link = None
            for a in soup.find_all("a", href=True):
                if any(k in a.text.lower() for k in keywords):
                    mention_link = requests.compat.urljoin(url, a["href"])
                    break

            details = {"url_checked": url, "mention_page": mention_link, "status": None,
                    "title": None, "keywords_found": [], "excerpts": [], "emails": [], "siren": None}

            def extract_info(txt):
                out = {}
                out["keywords_found"] = [k for k in keywords if k in txt]
                out["emails"] = re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", txt, re.I)
                out["siren"] = re.search(r"\b\d{3}\s?\d{3}\s?\d{3}\b", txt)
                if out["siren"]: out["siren"] = out["siren"].group()
                out["excerpts"] = txt[:400]
                return out

            if mention_link:
                r2 = requests.get(mention_link, timeout=5, headers=headers, allow_redirects=True)
                if r2.status_code == 200:
                    s2 = BeautifulSoup(r2.text, "html.parser")
                    txt2 = s2.get_text(" ", strip=True).lower()
                    details.update({"status": 200, "title": s2.title.string if s2.title else None})
                    details.update(extract_info(txt2))
                    details["exists"] = True
                    return details

            details.update(extract_info(text))
            details["exists"] = bool(details["keywords_found"])
            return details
        except Exception as e:
            print(f"⚠️ Erreur check_mentions_legales({url}):", e)
            return {"exists": False, "error": str(e)}

    def check_ssl(domain):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(3)
                s.connect((domain, 443))
                return True
        except:
            return False
        
    def get_certificate_info(domain, timeout=5):
        print(f"\n[DEBUG][SSL] ➜ Vérification SSL pour domaine : {domain}")
        try:
            ctx = ssl.create_default_context()
            print(f"[DEBUG][SSL] Tentative de connexion socket {domain}:443 ...")
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                print(f"[DEBUG][SSL] ✓ Socket ouverte sur {domain}")
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    print(f"[DEBUG][SSL] ✓ Handshake SSL réussi avec {domain}")
                    der = ssock.getpeercert(binary_form=True)
                    cert = ssock.getpeercert()  # dict form
            print(f"[DEBUG][SSL] ✓ Certificat reçu, conversion PEM ...")
            pem = ssl.DER_cert_to_PEM_cert(der)
            sha256 = hashlib.sha256(der).hexdigest()
            print(f"[DEBUG][SSL] ✓ Fingerprint SHA256 : {sha256[:12]}...")

            def _tuples_to_dict(tuples):
                out = {}
                for t in tuples:
                    for k,v in t:
                        out.setdefault(k, v)
                return out

            subject = _tuples_to_dict(cert.get("subject", ()))
            issuer = _tuples_to_dict(cert.get("issuer", ()))
            notBefore = cert.get("notBefore")
            notAfter = cert.get("notAfter")
            san = cert.get("subjectAltName", [])

            info = {
                "ssl_ok": True,
                "domain": domain,
                "pem": pem,
                "sha256_fingerprint": sha256,
                "subject": subject,
                "issuer": issuer,
                "notBefore": notBefore,
                "notAfter": notAfter,
                "subjectAltName": san
            }
            return info
        except Exception as e:
            return {"ssl_ok": False, "error": str(e), "domain": domain}

    search_results = duckduckgo_search(sender)
    official_site = search_results[0]["url"] if search_results else None

    official_ssl_ok = False
    official_mentions_ok = False
    if official_site:
        domain = tldextract.extract(official_site)
        domain = f"{domain.domain}.{domain.suffix}"
        official_ssl_ok = check_ssl(domain)
        official_mentions_ok = check_mentions_legales(official_site)

    mail_link_check = None
    if links:
        mail_link_check = {
            "url": links[0],
            "mentions_legales": check_mentions_legales(links[0]),
            "ssl_ok": check_ssl(tldextract.extract(links[0]).registered_domain)
        }

    print("\n[DEBUG] ----------------------")
    print("[DEBUG] Sujet :", subject)
    print("[DEBUG] Expéditeur :", sender)
    print("[DEBUG] Liens trouvés :", links)
    print("[DEBUG] Site officiel détecté :", official_site)


    WHITELIST = [
        "formalites@infos-airfrance.com",
        "no_reply@email.apple.com",
        
    ]

    is_whitelisted = sender.lower() in [w.lower() for w in WHITELIST]

    rapport = {
        
        "sender": sender,
        "official_site": official_site,
        "official_ssl_info": get_certificate_info(tldextract.extract(official_site).registered_domain) if official_site else None,
        "official_mentions_legales": check_mentions_legales(official_site) if official_site else None,
        "mail_link_check": {
            "url": links[0] if links else None,
            "mentions_legales": check_mentions_legales(links[0]) if links else None,
            "ssl_info": get_certificate_info(tldextract.extract(links[0]).registered_domain) if links else None
        } if links else None
    }
    print("🔎 Rapport pré-IA enrichi :", rapport)
    print("[DEBUG] Rapport complet JSON :")
    print(json.dumps(rapport, indent=2, ensure_ascii=False))

    prompt = f"""
    Analyse complète d’un mail suspect.

    === Informations brutes du mail ===
    - Sujet : {subject}
    - Expéditeur : {sender}
    - Corps (extrait) : {text[:2000]}
    - Liens trouvés : {links}

    === Données d’analyse web ===
    {rapport}

    Les objets ci-dessus contiennent :
    - Le certificat SSL complet (avec sujet, issuer, fingerprint, dates…)
    - Les détails extraits de la page de mentions légales (emails, siren, extraits, titres)
    - Le statut des liens (existence, contenu)

    Ta mission :
    1. Analyse TOUT : contenu du mail (ton, urgences, fautes, demande d’action), cohérence expéditeur ↔ domaine, et résultats web/SSL/Mentions légales.
    2. Donne la priorité aux preuves techniques :
    - Si le site analysé a un certificat SSL valide, un émetteur reconnu et des mentions légales officielles comportant un SIREN, une adresse et un éditeur, considère le mail comme probablement légitime même si son contenu est bancaire.
    - Le nom d’expéditeur n’a PAS à correspondre exactement au domaine du site car ce sont deux choses differentes, un site web n'envoie pas de mails.
    2bis. Si les preuves techniques sont absentes/indéterminées MAIS que le message est seulement informatif (pas de demande d’identifiants, paiement, clic de connexion, pièce jointe suspecte) : classe "neutre", mets un risque = 5 et recommande explicitement de ne cliquer sur aucun lien si l’expéditeur n’est pas connu.
    3. Ne classe un mail “frauduleux” que si les preuves techniques sont absentes ET/OU incohérentes, ou que le contenu contient des signes évidents de fraude.
    4. Donne un verdict clair (légitime/frauduleux/neutre) et un score de risque (0–10).
    5. Résume ton raisonnement en 2 phrases maximum, et inclue la recommandation en 1 phrase maximum.
    6.En cas de verdict “frauduleux”, ajoute toujours une recommandation claire : “Ne cliquez sur aucun lien, ne téléchargez aucune pièce jointe et signalez ou supprimez immédiatement le mail.”

    7. la date (future ou passée) ainsi que l'abscence de sujet d'un mail ne donne pas preuve de fraudes . ce sont des info neutres .

    Réponds uniquement en JSON clair :
    {{
    "verdict": "...",
    "risque": 0-10,
    "explication": "..."
    "recommendation": "..."
    }}
    """

    if is_whitelisted:
        prompt += f"\n⚠️ L’expéditeur {sender} est sur une liste blanche interne : il est considéré comme officiel et légitime.\n"

    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    payload = {"model": "mistral-small", "messages": [{"role": "user", "content": prompt}]}

    try:
        print("[DEBUG][IA] Envoi du prompt à Mistral ...")
        print(f"[DEBUG][IA] Taille du prompt : {len(prompt)} caractères")
        resp = requests.post(API_URL, headers=headers, json=payload, timeout=30)
        print(f"[DEBUG][IA] Statut HTTP Mistral : {resp.status_code}")
        out = resp.json()
        print("[DEBUG][IA] Réponse brute :", out)

        # ✅ Vérifie que la réponse contient bien 'choices'
        if resp.status_code == 200 and "choices" in out and out["choices"]:
            msg = out["choices"][0]["message"]["content"]
            print("✅ Réponse IA reçue :", msg)
            return jsonify({"ai_result": msg})
        else:
            err_msg = (
                out.get("message")
                or out.get("error", {}).get("message")
                or f"HTTP {resp.status_code}"
            )
            print("[⚠️][IA] Réponse non exploitable :", err_msg)
            return jsonify({
                "error": f"IA indisponible: {err_msg}. Server plein.",
                "raw_response": out
            }), 503

    except Exception as e:
        print("[ERROR][GLOBAL] Exception analyse_mail :", repr(e))
        return jsonify({"error": str(e)}), 500

@app.route("/ping")
def ping():
    return jsonify({"status": "alive"}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Port injecté par Render
    print(f"🚀 Serveur Flask lancé sur le port {port}")
    app.run(host="0.0.0.0", port=port)



