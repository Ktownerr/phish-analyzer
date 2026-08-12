"""
Unit tests for the analyzer core. These run anywhere with just
`pip install -r requirements.txt pytest` -- no AD/DB/VMs required.
Run with: pytest tests/
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.analyzer import analyze_raw_email

SAMPLE_PHISHING_EMAIL = """\
Delivered-To: victim@example.com
Return-Path: <attacker@evil-domain.xyz>
Received: from mail.evil-domain.xyz (mail.evil-domain.xyz [203.0.113.5])
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=evil-domain.xyz; dkim=fail header.d=evil-domain.xyz; dmarc=fail
From: "PayPal Support" <random123@evil-domain.xyz>
Reply-To: attacker2@totally-different.tk
To: victim@example.com
Subject: Urgent: Your account has been suspended
Date: Mon, 1 Jan 2024 12:00:00 -0000
Message-ID: <abc123@evil-domain.xyz>
Content-Type: text/html; charset="UTF-8"

<html><body>
<p>Dear customer, your account has been suspended. Click below to verify:</p>
<a href="http://192.168.1.1/verify-account">https://paypal.com/verify</a>
<a href="http://bit.ly/3xyzABC">Click here to secure your account</a>
</body></html>
"""

SAMPLE_LEGIT_EMAIL = """\
Delivered-To: alice@example.com
Return-Path: <newsletter@github.com>
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass
From: "GitHub" <newsletter@github.com>
To: alice@example.com
Subject: Your weekly digest
Date: Mon, 1 Jan 2024 12:00:00 -0000
Message-ID: <xyz@github.com>
Content-Type: text/plain; charset="UTF-8"

Here's what happened in your repos this week.
Check it out at https://github.com/notifications
"""


def test_phishing_email_scores_high():
    result = analyze_raw_email(SAMPLE_PHISHING_EMAIL)
    assert result["risk_score"] >= 60
    assert result["risk_level"] == "High"
    assert result["auth_results"]["spf"] == "fail"
    assert result["auth_results"]["dkim"] == "fail"
    assert result["auth_results"]["dmarc"] == "fail"


def test_phishing_email_flags_display_name_spoof():
    result = analyze_raw_email(SAMPLE_PHISHING_EMAIL)
    assert result["display_mismatch"]["suspicious"] is True


def test_phishing_email_flags_ip_url_and_shortener():
    result = analyze_raw_email(SAMPLE_PHISHING_EMAIL)
    hosts = [u["host"] for u in result["urls"]]
    assert "192.168.1.1" in hosts
    assert "bit.ly" in hosts


def test_legit_email_scores_low():
    result = analyze_raw_email(SAMPLE_LEGIT_EMAIL)
    assert result["risk_score"] < 30
    assert result["auth_results"]["spf"] == "pass"


def test_link_text_mismatch_detected():
    result = analyze_raw_email(SAMPLE_PHISHING_EMAIL)
    ip_url = next(u for u in result["urls"] if u["host"] == "192.168.1.1")
    assert any("Link text shows" in f for f in ip_url["flags"])
