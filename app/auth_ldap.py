"""
LDAP authentication against Active Directory.

Strategy: "bind as the user" auth.
  1. We take the username/password submitted on the login form.
  2. We attempt an LDAP simple bind to the Domain Controller AS THAT USER.
  3. If the bind succeeds, AD has already verified the password for us --
     we never store or check passwords ourselves.
  4. We then (optionally) verify the user belongs to the required AD group
     by rebinding as a read-only service account and searching for
     group membership.

Set these in your environment (see .env.example):
  AD_SERVER          e.g. ldap://192.168.56.10  (use ldaps:// once you set up TLS)
  AD_DOMAIN          e.g. corp.local
  AD_BASE_DN         e.g. DC=corp,DC=local
  AD_REQUIRED_GROUP  e.g. PhishAnalyzer-Users   (optional - leave blank to skip group check)
  AD_SERVICE_USER    e.g. svc-phishapp@corp.local   (read-only account, for group lookups)
  AD_SERVICE_PASS    password for the above
"""

import os
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException

AD_SERVER = os.environ.get("AD_SERVER", "ldap://192.168.56.10")
AD_DOMAIN = os.environ.get("AD_DOMAIN", "corp.local")
AD_BASE_DN = os.environ.get("AD_BASE_DN", "DC=corp,DC=local")
AD_REQUIRED_GROUP = os.environ.get("AD_REQUIRED_GROUP", "")  # optional
AD_SERVICE_USER = os.environ.get("AD_SERVICE_USER", "")
AD_SERVICE_PASS = os.environ.get("AD_SERVICE_PASS", "")

# ============================================================================
# DEV-ONLY BYPASS -- REMOVE BEFORE YOU DEMO/SUBMIT THIS PROJECT
# ----------------------------------------------------------------------------
# When DEV_MODE=true is set in the environment, login skips the real LDAP
# bind entirely and accepts ANY username with password "devpass". This lets
# you click through the full app UI before your AD VM is ready.
#
# This is NOT secure and must not be present in your final submission or
# demo -- your rubric almost certainly requires real AD authentication.
# To remove it: delete this whole block plus the "if DEV_MODE" check at the
# top of authenticate_user() below.
DEV_MODE = os.environ.get("DEV_MODE", "false").lower() == "true"
DEV_PASSWORD = "devpass"
# ============================================================================


def _user_principal(username: str) -> str:
    """Build a UPN like 'jdoe@corp.local' if a bare username was entered."""
    if "@" in username:
        return username
    return f"{username}@{AD_DOMAIN}"


def authenticate_user(username: str, password: str):
    """
    Returns (success: bool, error_message: str|None)
    """
    if not username or not password:
        return False, "Username and password required"

    # DEV-ONLY BYPASS -- see block near top of file. Remove before submission.
    if DEV_MODE:
        if password == DEV_PASSWORD:
            return True, None
        return False, f"Dev mode is on -- use password '{DEV_PASSWORD}'"

    upn = _user_principal(username)
    server = Server(AD_SERVER, get_info=ALL)

    # Step 1: bind as the user -- this is the actual authentication check.
    try:
        conn = Connection(server, user=upn, password=password, auto_bind=True)
    except LDAPException:
        return False, "Invalid username or password"

    # Step 2 (optional): verify group membership.
    if AD_REQUIRED_GROUP:
        try:
            in_group = _check_group_membership(server, username)
        finally:
            conn.unbind()
        if not in_group:
            return False, f"User is not a member of required group '{AD_REQUIRED_GROUP}'"
        return True, None

    conn.unbind()
    return True, None


def _check_group_membership(server: Server, username: str) -> bool:
    """Rebind as the service account and check the user's memberOf attribute."""
    if not AD_SERVICE_USER or not AD_SERVICE_PASS:
        # No service account configured -- skip the check rather than lock everyone out.
        return True

    try:
        svc_conn = Connection(
            server, user=AD_SERVICE_USER, password=AD_SERVICE_PASS, auto_bind=True
        )
        svc_conn.search(
            search_base=AD_BASE_DN,
            search_filter=f"(sAMAccountName={username})",
            search_scope=SUBTREE,
            attributes=["memberOf"],
        )
        if not svc_conn.entries:
            return False

        groups = svc_conn.entries[0].memberOf.values if "memberOf" in svc_conn.entries[0] else []
        svc_conn.unbind()
        return any(AD_REQUIRED_GROUP.lower() in g.lower() for g in groups)
    except LDAPException:
        return False
