# Sécurité Python — TP1 / TP2 / TP3

Dépôt des travaux pratiques du module *Programmation et sécurité Python avancée* (M1 Cybersécurité).
Chaque TP est un paquet autonome sous `src/tpN/`, lancé via un script Poetry.

## TP3 — Breach the target

Exploit automatisé qui enchaîne une phase **web** puis une phase **réseau** pour récupérer deux drapeaux,
sans intervention humaine :

1. **Fuzzing** : on teste une wordlist embarquée (`src/tp3/utils/wordlist.txt`) pour trouver l'endpoint caché.
2. **CAPTCHA** : l'image `/captcha.png` est téléchargée puis cassée par OCR (`pillow` + `pytesseract`,
   prétraitement niveaux de gris + seuil). La page livre alors `flag1`, un `host:port` et une clé d'encodage.
3. **Décodage réseau** : on se connecte au service TCP (`pwntools`), on décode chaque jeton
   (`base64` puis XOR avec la clé) et on répond dans la fenêtre de temps impartie. Après les rounds
   réussis, le serveur renvoie le drapeau final.

### Prérequis

- [Poetry](https://python-poetry.org/)
- **Tesseract OCR** (binaire système requis par `pytesseract`) :
  - Windows : `winget install --id UB-Mannheim.TesseractOCR`
  - Debian/Ubuntu : `sudo apt install tesseract-ocr`

### Installation

```bash
poetry lock
poetry install
```

### Utilisation

```bash
poetry run tp3 --target http://localhost:8080
```

Sortie attendue :

```
[+] FLAG1: ESGI{web_...}
[+] FLAG_FINAL: ESGI{chain_...}
```

### Cible locale (développement)

```bash
docker load -i tp3-target.tar.gz
docker compose up
# Web : http://localhost:8080   TCP : localhost:9090
```

## Autres TP

```bash
poetry run tp1   # analyse de trafic réseau (scapy)
poetry run tp2   # triage de malware
```

## Tests

```bash
poetry run pytest
```

## Structure

```
src/tp3/
  main.py            # breach_web + breach_network + main
  utils/
    args.py          # arguments CLI (--target, --verbose)
    config.py        # logger
    fuzzer.py        # découverte d'endpoints
    captcha.py       # téléchargement + OCR du CAPTCHA
    session.py       # franchissement du CAPTCHA, récupération du flag 1
    decoder.py       # décodage base64+XOR du flux TCP
    wordlist.txt     # wordlist embarquée
```
