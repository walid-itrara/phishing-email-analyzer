@'
# Phishing Email Analyzer (SOC Triage Tool)

Outil Python d'analyse automatisée d'e-mails suspects (`.eml`) permettant de détecter les tentatives de phishing, vérifier l'authenticité de l'expéditeur (`SPF`, `DKIM`, `DMARC`), extraire les indicateurs de compromission (IOCs : URLs, hash `SHA-256` des pièces jointes) et vérifier la réputation via l'API **VirusTotal**.

## Fonctionnalités
- **Analyse d'en-têtes & Anti-Spoofing :** Vérification `SPF`, `DKIM`, `DMARC` et détection des anomalies `From` vs `Return-Path`.
- **Extraction d'IOCs :** Extraction et neutralisation (*defanging*) des liens suspects + calcul d'empreinte cryptographique `SHA-256` des pièces jointes.
- **Threat Intelligence :** Intégration de l'API VirusTotal v3 pour vérifier la réputation des domaines et URLs.
- **Génération de rapport :** Résumé dans le terminal et export complet dans `analysis_report.txt`.

## Exemple de résultat (Terminal)
```text
$ python email_analyzer.py sample.eml
Sender            : noreply@paypal-security.com [Suspicious]
Return-Path       : bounce@shady-mailer-host.ru
SPF               : Fail
DKIM              : Fail
DMARC             : Fail
Links             : 2 (1 malicious)
Attachment        : invoice_update.pdf (SHA-256: b3a8e0e1f9...)
Domain Reputation : Malicious (VirusTotal / Heuristic)