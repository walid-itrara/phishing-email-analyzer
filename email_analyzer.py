import os
import re
import sys
import hashlib
import base64
import urllib.parse
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
import requests

VT_API_KEY = os.getenv("VT_API_KEY", "")


def parse_eml(file_path: str) -> dict:
    path = Path(file_path)
    if not path.is_file():
        print(f"[!] Erreur: Fichier '{file_path}' introuvable.")
        sys.exit(1)

    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    html_body, plain_body = "", ""
    attachments = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        ctype = part.get_content_type()

        if disposition == "attachment":
            raw_bytes = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": part.get_filename() or "fichier_inconnu",
                "content_type": ctype,
                "size": len(raw_bytes),
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            })
        elif ctype == "text/html":
            html_body += part.get_content()
        elif ctype == "text/plain":
            plain_body += part.get_content()

    return {
        "from": msg.get("From", ""),
        "return_path": msg.get("Return-Path", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "auth_results": msg.get("Authentication-Results", ""),
        "plain_body": plain_body,
        "html_body": html_body,
        "attachments": attachments,
    }


def extract_auth_status(auth_header: str, protocol: str) -> str:
    if not auth_header:
        return "None"
    match = re.search(rf"\b{protocol}\s*=\s*([a-zA-Z0-9_-]+)", auth_header, re.IGNORECASE)
    return match.group(1).capitalize() if match else "None"


def analyze_indicators(parsed_email: dict) -> dict:
    _, from_addr = parseaddr(parsed_email["from"])
    _, return_addr = parseaddr(parsed_email["return_path"])

    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    return_domain = return_addr.split("@")[-1].lower() if "@" in return_addr else ""

    auth_header = parsed_email["auth_results"]
    spf = extract_auth_status(auth_header, "spf")
    dkim = extract_auth_status(auth_header, "dkim")
    dmarc = extract_auth_status(auth_header, "dmarc")

    sender_suspicious = (
        spf.lower() == "fail"
        or dkim.lower() == "fail"
        or dmarc.lower() == "fail"
        or (from_domain and return_domain and from_domain != return_domain and dmarc.lower() != "pass")
    )

    combined_body = f"{parsed_email['plain_body']}\n{parsed_email['html_body']}"
    urls = sorted(set(re.findall(r"https?://[^\s\"'<>]+", combined_body)))

    return {
        "sender_address": from_addr or parsed_email["from"],
        "sender_domain": from_domain,
        "return_path_address": return_addr,
        "sender_suspicious": sender_suspicious,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "urls": urls,
        "attachments": parsed_email["attachments"],
    }


def check_domain_reputation(domain: str) -> str:
    if not domain:
        return "Unknown"

    if VT_API_KEY:
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VT_API_KEY},
                timeout=8,
            )
            if resp.status_code == 200:
                stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
                if stats.get("malicious", 0) > 0:
                    return f"Malicious (VirusTotal: {stats['malicious']} detections)"
                if stats.get("suspicious", 0) > 0:
                    return f"Suspicious (VirusTotal: {stats['suspicious']} detections)"
                return "Safe (VirusTotal)"
        except requests.RequestException:
            pass

    suspicious_keywords = ["security", "verify", "login", "update", "account"]
    if any(k in domain for k in suspicious_keywords) and "-" in domain:
        return "Malicious (Heuristic / Threat Intel Simulation)"
    return "Safe"


def check_url_reputation(url: str) -> bool:
    if VT_API_KEY:
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VT_API_KEY},
                timeout=8,
            )
            if resp.status_code == 200:
                stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
                return stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0
        except requests.RequestException:
            pass

    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "http" or "verify" in url.lower() or "-" in parsed.netloc


def defang_url(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def generate_report(file_path: str, parsed: dict, analysis: dict, output_file: str = "analysis_report.txt"):
    domain_rep = check_domain_reputation(analysis["sender_domain"])
    url_results = [(u, check_url_reputation(u)) for u in analysis["urls"]]
    malicious_count = sum(1 for _, is_bad in url_results if is_bad)

    sender_tag = " [Suspicious]" if analysis["sender_suspicious"] else ""

    if not analysis["attachments"]:
        att_summary = "None"
    else:
        att_names = [f"{a['filename']} (SHA-256: {a['sha256'][:10]}...)" for a in analysis["attachments"]]
        att_summary = ", ".join(att_names)

    cli_output = (
        f"$ python email_analyzer.py {file_path}\n"
        f"Sender            : {analysis['sender_address']}{sender_tag}\n"
        f"Return-Path       : {analysis['return_path_address'] or 'None'}\n"
        f"SPF               : {analysis['spf']}\n"
        f"DKIM              : {analysis['dkim']}\n"
        f"DMARC             : {analysis['dmarc']}\n"
        f"Links             : {len(url_results)} ({malicious_count} malicious)\n"
        f"Attachment        : {att_summary}\n"
        f"Domain Reputation : {domain_rep}"
    )

    print("\n" + cli_output + "\n")

    # Export détaillé dans le fichier de rapport
    report_lines = [
        "====================================================",
        "           PHISHING EMAIL ANALYSIS REPORT           ",
        "====================================================",
        f"Analyzed File     : {file_path}",
        f"Subject           : {parsed['subject']}",
        f"Date              : {parsed['date']}",
        "----------------------------------------------------",
        cli_output,
        "----------------------------------------------------",
        "EXTRACTED IOCs - URLs (Defanged):",
    ]
    for url, is_bad in url_results:
        tag = "[MALICIOUS]" if is_bad else "[CLEAN]"
        report_lines.append(f"  - {tag:11} {defang_url(url)}")

    report_lines.append("\nEXTRACTED IOCs - Attachments:")
    for att in analysis["attachments"]:
        report_lines.append(f"  - File : {att['filename']} ({att['size']} bytes)")
        report_lines.append(f"    Hash : {att['sha256']}")

    report_lines.append("====================================================")

    Path(output_file).write_text("\n".join(report_lines), encoding="utf-8")
    print(f"[+] Rapport d'investigation sauvegardé dans : {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python email_analyzer.py <sample.eml>")
        sys.exit(1)

    eml_file = sys.argv[1]
    parsed_data = parse_eml(eml_file)
    analysis_data = analyze_indicators(parsed_data)
    generate_report(eml_file, parsed_data, analysis_data)