"""
Core phishing analysis engine.

Takes a raw email (headers + body, as you'd get from "View Source" / "Show
Original" in Gmail/Outlook) and returns a structured result:
  - authentication results (SPF/DKIM/DMARC)
  - extracted URLs with basic red-flag checks
  - attachment metadata
  - a numeric risk score
  - a human-readable "why this is suspicious" writeup

No network calls / no live DNS lookups are made here -- we trust the
Authentication-Results header the receiving mail server already stamped.
This keeps the analyzer fast, offline-friendly, and safe to run against
untrusted content (we never fetch attacker-controlled URLs).
"""

import re
import hashlib
from email import message_from_string
from email.utils import parseaddr, getaddresses
from urllib.parse import urlparse

URL_REGEX = re.compile(r'https?://[^\s\'"<>\)\]]+', re.IGNORECASE)

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "work", "loan", "gq", "tk", "ml", "cf",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".com",
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
}


def analyze_raw_email(raw_email: str) -> dict:
    msg = message_from_string(raw_email)

    headers = _extract_headers(msg)
    auth_results = _parse_authentication_results(msg)
    urls = _extract_urls(msg)
    attachments = _extract_attachments(msg)
    display_mismatch = _check_display_name_spoof(msg)

    score, reasons = _score_risk(auth_results, urls, attachments, display_mismatch, headers)

    return {
        "headers": headers,
        "auth_results": auth_results,
        "urls": urls,
        "attachments": attachments,
        "display_mismatch": display_mismatch,
        "risk_score": score,
        "risk_level": _risk_level(score),
        "reasons": reasons,
    }


# --- Header extraction ------------------------------------------------------

def _extract_headers(msg) -> dict:
    from_name, from_addr = parseaddr(msg.get("From", ""))
    reply_to_name, reply_to_addr = parseaddr(msg.get("Reply-To", ""))

    return {
        "from_display_name": from_name,
        "from_address": from_addr,
        "reply_to_address": reply_to_addr,
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
        "received_hops": len(msg.get_all("Received", []) or []),
    }


def _check_display_name_spoof(msg) -> dict:
    """Flags cases like: From: 'PayPal Support <randomstring@evil.com>'"""
    from_name, from_addr = parseaddr(msg.get("From", ""))
    reply_to_name, reply_to_addr = parseaddr(msg.get("Reply-To", ""))

    flags = []
    if reply_to_addr and from_addr and reply_to_addr.lower() != from_addr.lower():
        flags.append(
            f"Reply-To ({reply_to_addr}) differs from From address ({from_addr})"
        )

    known_brands = ["paypal", "microsoft", "apple", "amazon", "bank", "irs", "google", "docusign"]
    name_lower = from_name.lower()
    for brand in known_brands:
        if brand in name_lower and from_addr and brand not in from_addr.lower():
            flags.append(
                f"Display name references '{brand.title()}' but sender domain is '{from_addr.split('@')[-1] if '@' in from_addr else from_addr}'"
            )

    return {"flags": flags, "suspicious": len(flags) > 0}


# --- Authentication-Results (SPF/DKIM/DMARC) --------------------------------

def _parse_authentication_results(msg) -> dict:
    """
    Parses the Authentication-Results header, e.g.:
      spf=pass smtp.mailfrom=example.com; dkim=fail header.d=example.com; dmarc=pass
    Falls back to 'none' if the header is missing (common in lab-generated test emails).
    """
    header_value = msg.get("Authentication-Results", "")

    results = {"spf": "none", "dkim": "none", "dmarc": "none", "raw": header_value}

    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"{mechanism}=(\w+)", header_value, re.IGNORECASE)
        if match:
            results[mechanism] = match.group(1).lower()

    # Some servers split SPF into its own "Received-SPF" header instead.
    if results["spf"] == "none":
        spf_header = msg.get("Received-SPF", "")
        spf_match = re.search(r"^(\w+)", spf_header)
        if spf_match:
            results["spf"] = spf_match.group(1).lower()

    return results


# --- URL extraction ----------------------------------------------------------

def _extract_urls(msg) -> list:
    body_text = _get_body_text(msg)
    body_html = _get_body_html(msg)

    found = set(URL_REGEX.findall(body_text)) | set(URL_REGEX.findall(body_html))

    # Pull the (href, display_text) pairs out of the HTML body for mismatch detection.
    href_display_pairs = re.findall(
        r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', body_html, re.IGNORECASE | re.DOTALL
    )

    results = []
    seen = set()
    for url in found:
        if url in seen:
            continue
        seen.add(url)
        results.append(_evaluate_url(url))

    # Add flags for anchor text that doesn't match the href (classic phishing trick).
    for href, display in href_display_pairs:
        display_clean = re.sub("<[^<]+?>", "", display).strip()
        display_urls = URL_REGEX.findall(display_clean)
        if display_urls and display_urls[0].rstrip("/") != href.rstrip("/"):
            for r in results:
                if r["url"] == href:
                    r["flags"].append(
                        f"Link text shows '{display_urls[0]}' but actually points to '{href}'"
                    )

    return results


def _evaluate_url(url: str) -> dict:
    flags = []
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except ValueError:
        host = ""

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        flags.append("URL uses a raw IP address instead of a domain name")

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Uses uncommon/high-abuse TLD '.{tld}'")

    if host in URL_SHORTENERS:
        flags.append(f"Uses URL shortener '{host}' which hides the real destination")

    if "@" in url.split("//")[-1].split("/")[0]:
        flags.append("URL contains '@' before the host -- classic redirect obfuscation trick")

    if host.count("-") >= 3:
        flags.append("Domain has an unusually high number of hyphens (common in lookalike domains)")

    return {"url": url, "host": host, "flags": flags}


# --- Attachments --------------------------------------------------------------

def _extract_attachments(msg) -> list:
    attachments = []
    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        filename = part.get_filename()
        if "attachment" not in disposition.lower() and not filename:
            continue
        if part.is_multipart():
            continue

        payload = part.get_payload(decode=True) or b""
        sha256 = hashlib.sha256(payload).hexdigest() if payload else ""
        ext = ("." + filename.rsplit(".", 1)[-1].lower()) if filename and "." in filename else ""

        flags = []
        if filename and filename.lower().count(".") >= 2:
            parts_of_name = filename.lower().split(".")
            if parts_of_name[-2] in {"pdf", "doc", "jpg", "png", "txt"} and ext in EXECUTABLE_EXTENSIONS:
                flags.append(f"Double extension disguise: '{filename}' looks like a document but is executable")
        if ext in EXECUTABLE_EXTENSIONS:
            flags.append(f"Executable file type ({ext})")
        if ext in MACRO_EXTENSIONS:
            flags.append(f"Macro-enabled Office file ({ext}) -- can run code on open")

        attachments.append({
            "filename": filename or "(unnamed)",
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "sha256": sha256,
            "flags": flags,
        })
    return attachments


def _get_body_text(msg) -> str:
    return _get_body_by_type(msg, "text/plain")


def _get_body_html(msg) -> str:
    return _get_body_by_type(msg, "text/html")


def _get_body_by_type(msg, content_type: str) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == content_type and "attachment" not in str(part.get("Content-Disposition", "")):
                try:
                    return part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    return ""
        return ""
    else:
        if msg.get_content_type() == content_type:
            try:
                return msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                return ""
        return ""


# --- Scoring --------------------------------------------------------------

def _score_risk(auth_results, urls, attachments, display_mismatch, headers) -> tuple:
    score = 0
    reasons = []

    if auth_results["spf"] == "fail":
        score += 20
        reasons.append("SPF check failed -- sending server is not authorized for this domain")
    elif auth_results["spf"] == "softfail":
        score += 10
        reasons.append("SPF soft-fail -- sending server is questionable for this domain")

    if auth_results["dkim"] == "fail":
        score += 20
        reasons.append("DKIM signature failed -- message content or sender may have been tampered with")

    if auth_results["dmarc"] == "fail":
        score += 20
        reasons.append("DMARC alignment failed -- message fails the domain's own anti-spoofing policy")

    if auth_results["spf"] == "none" and auth_results["dkim"] == "none" and auth_results["dmarc"] == "none":
        score += 5
        reasons.append("No authentication results present at all (unverifiable sender)")

    for flag in display_mismatch["flags"]:
        score += 15
        reasons.append(flag)

    for url in urls:
        for flag in url["flags"]:
            score += 10
            reasons.append(f"[{url['host']}] {flag}")

    for att in attachments:
        for flag in att["flags"]:
            score += 25
            reasons.append(f"[{att['filename']}] {flag}")

    if headers.get("received_hops", 0) == 0:
        score += 5
        reasons.append("No 'Received' hops found -- header may be incomplete or forged")

    return min(score, 100), reasons


def _risk_level(score: int) -> str:
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    if score > 0:
        return "Low"
    return "Minimal"
