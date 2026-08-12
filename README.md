# Phishing Email Analyzer

Paste a raw email (headers + body) and get back:
- SPF / DKIM / DMARC results
- Extracted URLs with red-flag checks (shorteners, raw IPs, link-text mismatches, etc.)
- Attachment metadata (hash, type, double-extension / macro detection)
- A numeric risk score and a plain-English "why this is suspicious" writeup

Authentication is done against an Active Directory domain via LDAP bind.

## Architecture

- **Windows Server 2025 VM**: Active Directory Domain Services (the identity source)
- **Ubuntu Server VM**: runs this app + PostgreSQL, via Docker Compose
- **GitHub Actions self-hosted runner** on the Ubuntu VM: redeploys automatically on push to `main`

## 1. Local dev (no AD/Docker needed yet)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest

# Run the analyzer unit tests (pure logic, no AD/DB required)
pytest tests/ -v

# Run the app with a local SQLite DB and no AD (auth will fail until AD_SERVER is set)
uvicorn app.main:app --reload
```

Visit http://localhost:8000

## 2. Set up Active Directory (Windows Server 2025 VM)

1. Install the **Active Directory Domain Services** role in Server Manager.
2. Promote the server to a new forest, e.g. domain `corp.local`.
3. In **Active Directory Users and Computers**:
   - Create an OU, e.g. `AppUsers`.
   - Create a few test user accounts.
   - Create a security group `PhishAnalyzer-Users` and add the test accounts to it.
   - (Optional but recommended) Create a read-only service account, e.g. `svc-phishapp`, used only for group-membership lookups.
4. Confirm the DC's IP address (e.g. `192.168.56.10`) — you'll need it for `.env`.

## 3. Configure the app

```bash
cp .env.example .env
```

Edit `.env` with your real AD server IP, domain, base DN, and (optionally) the required group / service account. Never commit `.env`.

## 4. Run with Docker Compose (Ubuntu Server VM)

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker

git clone <your-repo-url>
cd phish-analyzer
cp .env.example .env   # fill in real values
docker compose up -d --build
```

Visit `http://<ubuntu-vm-ip>:8000`. Log in with an AD account from `corp.local`.

Verify the LDAP path works before troubleshooting the app:
```bash
sudo apt install -y ldap-utils
ldapsearch -x -H ldap://<AD-IP> -D "testuser@corp.local" -W -b "DC=corp,DC=local"
```

## 5. GitHub auto-deploy setup (self-hosted runner)

Because the Ubuntu VM is likely on a private/NAT network, GitHub's cloud runners can't reach it — so the runner has to live **on** the VM itself and pull from GitHub, rather than GitHub pushing to the VM.

1. On GitHub: repo → **Settings → Actions → Runners → New self-hosted runner**, choose Linux.
2. Follow the generated commands on the Ubuntu VM (downloads the runner, configures it with a token tied to your repo).
3. Install it as a service so it survives reboots:
   ```bash
   sudo ./svc.sh install
   sudo ./svc.sh start
   ```
4. Push to `main` — `.github/workflows/deploy.yml` will run on the VM, rebuild the containers, and restart the app.

Check runner status any time: repo → **Settings → Actions → Runners** (should show "Idle" or "Active", not offline).

## Project layout

```
app/
  main.py          FastAPI routes (login, analyze, history)
  auth_ldap.py      LDAP bind authentication against AD
  analyzer.py       Core parsing/scoring logic (SPF/DKIM/DMARC, URLs, attachments)
  db.py             SQLAlchemy models + persistence
  templates/        Jinja2 HTML templates
  static/           CSS
tests/
  test_analyzer.py  Unit tests for the analyzer (no VMs required)
.github/workflows/
  deploy.yml        Self-hosted runner deploy workflow
docker-compose.yml  App + Postgres
Dockerfile
.env.example
```

## Notes on the auth design

- The app **never stores or checks passwords itself** — it does an LDAP bind to the domain controller as the submitted user. If AD accepts the password, the bind succeeds; if not, it fails. This is the standard "bind auth" pattern and keeps password handling entirely inside AD, where it belongs.
- Group-membership gating (`AD_REQUIRED_GROUP`) is optional — if you leave it and the service account blank, any valid AD user can log in. Recommended to enable it for the demo so you can show access control working (add/remove a user from the group live).
- Swap `ldap://` for `ldaps://` (port 636) once you've issued a certificate on the DC, for a stronger security story in your writeup/demo.
