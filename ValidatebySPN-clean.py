#!/usr/bin/env python3
"""
Azure Entra ID Client Secret Validator + Saviynt Integration
=============================================================
Two modes:
  1. Manual  - paste a client ID + secret to validate against Microsoft Graph
  2. Saviynt - enter a Service Principal Name, pull account info from
               Saviynt EIC, checkout credential from PAM vault, then
               validate automatically

Usage:
    python validate_secret.py
"""

import sys
import json
import time
import getpass
from urllib import request, parse, error

# ======================================================================
# AZURE TENANT (constant - all SPNs live in this tenant)
# ======================================================================
TENANT_ID = ""

# ======================================================================
# MASTER SPN - used to silently grant API permissions to target SPNs
# Must have: AppRoleAssignment.ReadWrite.All
# ======================================================================
MASTER_CLIENT_ID     = ""   # <-- paste your master SPN Application (Client) ID
MASTER_CLIENT_SECRET = ""   # <-- paste your master SPN client secret

# ======================================================================
# ENTRA ID GROUP - SaviyntDemoUsers
# ======================================================================
ENTRA_GROUP_OBJECT_ID = ""
ENTRA_GROUP_NAME      = ""

# ======================================================================
# SAVIYNT CONNECTION DETAILS
# ======================================================================
SAVIYNT_BASE_URL  = ""
SAVIYNT_USERNAME  = ""
SAVIYNT_PASSWORD  = ""

# Saviynt endpoint / connection (constant for all SPN accounts)
SAVIYNT_ENDPOINT   = ""
SAVIYNT_CONNECTION = ""

# Custom attribute mapping (stored by the rotation connector)
CUSTOM_ATTR_MAP = {
    "customproperty41": "Application (Client) ID",
    "customproperty42": "Object ID",
    "customproperty43": "Client Secret (legacy - now via PAM checkout)",
}

# PAM checkout settings
PAM_CHECKOUT_DURATION   = 30        # minutes
PAM_MAX_POLL_ATTEMPTS   = 30
PAM_POLL_INTERVAL_SECS  = 5

# ======================================================================
# AZURE RESOURCE MANAGER (ARM) - for VM listing (COMMENTED OUT)
# ======================================================================
AZURE_SUBSCRIPTION_ID = ""
AZURE_RESOURCE_GROUP  = ""

SEP = "-" * 64


# ======================================================================
# HTTP HELPERS
# ======================================================================
def _post_json(url, payload, headers=None):
    """POST JSON and return parsed response."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, headers=hdrs)
    try:
        with request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return {"error": f"HTTP {e.code}", "detail": body}


def _post_form(url, form_data, headers=None):
    """POST form-encoded data and return parsed response."""
    hdrs = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        hdrs.update(headers)
    data = parse.urlencode(form_data).encode("utf-8")
    req = request.Request(url, data=data, headers=hdrs)
    try:
        with request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return {"error": f"HTTP {e.code}", "detail": body}


def _get_json(url, headers=None):
    """GET and return parsed JSON response."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = request.Request(url, headers=hdrs)
    try:
        with request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return {"error": f"HTTP {e.code}", "detail": body}


def _delete_json(url, headers=None):
    """DELETE and return parsed JSON response (or empty dict on 204)."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = request.Request(url, headers=hdrs, method="DELETE")
    try:
        with request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body.strip() else {}
    except error.HTTPError as e:
        if e.code == 204:
            return {}
        body = e.read().decode("utf-8", errors="replace")
        return {"error": f"HTTP {e.code}", "detail": body}


# ======================================================================
# MICROSOFT GRAPH APP ROLE IDs (well-known for Microsoft Graph)
# Resource App ID for Microsoft Graph: 00000003-0000-0000-c000-000000000000
# ======================================================================
MS_GRAPH_RESOURCE_APP_ID = "00000003-0000-0000-c000-000000000000"

# App roles to grant to the target SPN so the Graph exploration calls work.
# Each tuple: (appRoleId, description)
REQUIRED_APP_ROLES = [
    ("df021288-bdef-4463-88db-98f22de89214", "User.Read.All"),
    ("5b567255-7703-4780-807c-7be8301ae99b", "Group.Read.All"),
]


# ======================================================================
# MASTER SPN HELPERS - silently grant / revoke API permissions
# ======================================================================
def _get_master_token():
    """Authenticate the master SPN and return an access token."""
    if not MASTER_CLIENT_ID or not MASTER_CLIENT_SECRET:
        return None
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    resp = _post_form(url, {
        "grant_type": "client_credentials",
        "client_id": MASTER_CLIENT_ID,
        "client_secret": MASTER_CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default",
    })
    return resp.get("access_token")


def _resolve_service_principal_id(master_token, app_client_id):
    """Look up the service principal object ID for a given appId."""
    safe = "/?&=$'"
    ep = f"servicePrincipals?$filter=appId eq '{app_client_id}'&$select=id,appId,displayName"
    url = f"https://graph.microsoft.com/v1.0/{parse.quote(ep, safe=safe)}"
    resp = _get_json(url, {"Authorization": f"Bearer {master_token}"})
    sps = resp.get("value", [])
    if sps:
        return sps[0].get("id")
    return None


def _resolve_graph_service_principal_id(master_token):
    """Look up the service principal object ID for Microsoft Graph itself."""
    return _resolve_service_principal_id(master_token, MS_GRAPH_RESOURCE_APP_ID)


def _get_existing_role_assignments(master_token, sp_id):
    """Get all appRoleAssignments already on a service principal."""
    url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{sp_id}/appRoleAssignments"
    resp = _get_json(url, {"Authorization": f"Bearer {master_token}"})
    return resp.get("value", [])


def grant_graph_permissions(target_client_id):
    """Use the master SPN to grant required Graph API permissions to the target SPN.

    Called early so Azure has time to propagate the role assignments before
    Graph calls are made. Runs silently with no console output.

    Returns a list of appRoleAssignment IDs that were newly created (for optional
    cleanup later), or an empty list if nothing was granted / master not configured.
    """
    if not MASTER_CLIENT_ID or not MASTER_CLIENT_SECRET:
        return []

    master_token = _get_master_token()
    if not master_token:
        return []

    target_sp_id = _resolve_service_principal_id(master_token, target_client_id)
    if not target_sp_id:
        return []

    graph_sp_id = _resolve_graph_service_principal_id(master_token)
    if not graph_sp_id:
        return []

    existing = _get_existing_role_assignments(master_token, target_sp_id)
    existing_role_ids = {a.get("appRoleId") for a in existing}

    created_ids = []
    for role_id, role_name in REQUIRED_APP_ROLES:
        if role_id in existing_role_ids:
            continue

        url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{target_sp_id}/appRoleAssignments"
        payload = {
            "principalId": target_sp_id,
            "resourceId":  graph_sp_id,
            "appRoleId":   role_id,
        }
        resp = _post_json(url, payload, {"Authorization": f"Bearer {master_token}"})
        if "error" not in resp:
            assignment_id = resp.get("id", "")
            created_ids.append(assignment_id)

    # Brief wait for Azure to propagate the role assignments
    if created_ids:
        time.sleep(5)

    return created_ids


def revoke_graph_permissions(target_client_id, assignment_ids):
    """Use the master SPN to revoke previously granted appRoleAssignments.

    Runs silently. Only revokes IDs created by grant_graph_permissions() in this run.
    """
    if not assignment_ids or not MASTER_CLIENT_ID or not MASTER_CLIENT_SECRET:
        return

    master_token = _get_master_token()
    if not master_token:
        return

    target_sp_id = _resolve_service_principal_id(master_token, target_client_id)
    if not target_sp_id:
        return

    for aid in assignment_ids:
        url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{target_sp_id}/appRoleAssignments/{aid}"
        _delete_json(url, {"Authorization": f"Bearer {master_token}"})


# ======================================================================
# MICROSOFT GRAPH HELPERS
# ======================================================================
def get_ms_access_token(tenant_id, client_id, client_secret):
    """Authenticate via client-credentials flow."""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    return _post_form(url, {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    })


def call_graph(access_token, endpoint):
    """GET from Microsoft Graph v1.0."""
    safe = "/?&=$'"
    url = f"https://graph.microsoft.com/v1.0/{parse.quote(endpoint, safe=safe)}"
    return _get_json(url, {"Authorization": f"Bearer {access_token}"})


def list_group_members(access_token, group_id, group_name):
    """List all members of an Entra ID group by Object ID."""
    print(f"\n[INFO] Fetching members of Entra ID group '{group_name}' ...")
    print(f"       Group Object ID: {group_id}")

    members_ep = f"groups/{group_id}/members?$select=id,displayName,userPrincipalName,mail,accountEnabled"
    members_resp = call_graph(access_token, members_ep)

    if "error" in members_resp:
        print(f"[WARN] Could not retrieve group members.")
        print(f"       {members_resp.get('error', '')}")
        if members_resp.get("detail"):
            detail = members_resp["detail"]
            try:
                detail_obj = json.loads(detail)
                msg = detail_obj.get("error", {}).get("message", detail[:300])
                print(f"       {msg}")
            except Exception:
                print(f"       {detail[:300]}")
        return

    members = members_resp.get("value", [])
    print(f"[OK]   {len(members)} member(s) found in group '{group_name}'.\n")

    if members:
        print(f"       {'#':<4s} {'Display Name':<30s} {'UPN / Email':<40s} {'Enabled':<10s} {'Object ID'}")
        print(f"       {'-'*4:<4s} {'-'*30:<30s} {'-'*40:<40s} {'-'*10:<10s} {'-'*36}")
        for i, m in enumerate(members, 1):
            display  = m.get("displayName", "N/A")
            upn      = m.get("userPrincipalName") or m.get("mail") or "N/A"
            enabled  = str(m.get("accountEnabled", "N/A"))
            obj_id   = m.get("id", "N/A")
            print(f"       {i:<4d} {display:<30s} {upn:<40s} {enabled:<10s} {obj_id}")
    else:
        print("       (no members found)")



# ======================================================================
# AZURE RESOURCE MANAGER HELPERS  (COMMENTED OUT - replaced by group members)
# ======================================================================
# def get_arm_access_token(tenant_id, client_id, client_secret):
#     url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
#     return _post_form(url, {
#         "grant_type": "client_credentials",
#         "client_id": client_id,
#         "client_secret": client_secret,
#         "scope": "https://management.azure.com/.default",
#     })
#
# def call_arm(access_token, path):
#     url = f"https://management.azure.com{path}"
#     return _get_json(url, {"Authorization": f"Bearer {access_token}"})
#
# def list_vms(tenant_id, client_id, client_secret, subscription_id, resource_group):
#     ...


# ======================================================================
# SAVIYNT HELPERS
# ======================================================================
def saviynt_login(base_url, username, password):
    """Authenticate to Saviynt and return (access_token, refresh_token, raw_resp)."""
    url = f"{base_url}/ECM/api/login"
    resp = _post_json(url, {"username": username, "password": password})
    if "error" in resp:
        return None, None, resp

    access_token = resp.get("access_token") or resp.get("token")
    refresh_token = resp.get("refresh_token")
    if not refresh_token:
        result = resp.get("result")
        if isinstance(result, dict):
            refresh_token = result.get("refresh_token")

    if not access_token:
        return None, None, {"error": "No token in response", "detail": json.dumps(resp)}

    return access_token, refresh_token, resp


def saviynt_get_account(base_url, token, account_name, endpoint):
    """Call Saviynt getAccounts and return the response.

    Uses advsearchcriteria with name for exact account match.
    """
    url = f"{base_url}/ECM/api/v5/getAccounts"
    resp = _post_json(url, {
        "endpoint": endpoint,
        "advsearchcriteria": {
            "name": account_name,
        },
        "max": 1,
        "offset": 0,
    }, {"Authorization": f"Bearer {token}"})
    return resp


def saviynt_generate_llt(base_url, refresh_token, account_key):
    """Generate a Long-Lasting Token (LLT) for PAM vault checkout."""
    url = f"{base_url}/ECM/oauth/access_token_withissuer"
    resp = _post_form(url, {
        "grant_type":    "refresh_token",
        "refresh_token": refresh_token,
        "accountId":     str(account_key),
    })

    if "error" in resp:
        return None, resp

    llt = resp.get("access_token")
    if not llt:
        result = resp.get("result")
        if isinstance(result, dict):
            llt = result.get("access_token")

    if not llt:
        return None, {"error": "No LLT in response", "detail": json.dumps(resp)}

    return llt, resp


def saviynt_checkout_credential(base_url, llt_token, account_key,
                                 duration=30, max_attempts=30, poll_interval=5):
    """Checkout a credential from the Saviynt PAM vault.

    Polls on TASK_NOT_FOUND_OR_NOT_COMPLETED until the credential is ready.
    Returns (client_secret, account_name, raw_response) or (None, None, error_dict).
    """
    url = f"{base_url}/ECMv6/api/pam/account/checkout"
    headers = {
        "Authorization": f"Bearer {llt_token}",
        "Content-Type":  "application/json",
    }
    payload = {"accountId": int(account_key), "duration": duration}

    cred_resp = None

    for attempt in range(1, max_attempts + 1):
        print(f"       Checkout attempt {attempt}/{max_attempts} ...", end="", flush=True)

        resp = _post_json(url, payload, headers)

        if "error" in resp:
            detail = resp.get("detail", "")
            if "TASK_NOT_FOUND_OR_NOT_COMPLETED" in detail:
                print(f" task not ready, waiting {poll_interval}s ...")
                time.sleep(poll_interval)
                continue
            else:
                print(" FAILED")
                return None, None, resp
        else:
            print(" Success!")
            cred_resp = resp
            break

    if cred_resp is None:
        return None, None, {"error": "Checkout did not complete within polling window"}

    # Extract the secret - handle various Saviynt response structures
    client_secret = None
    account_name  = None

    pw = cred_resp.get("password")
    if pw is not None:
        if isinstance(pw, str):
            client_secret = pw
        elif isinstance(pw, dict):
            client_secret = pw.get("value")
        else:
            client_secret = str(pw)

    if client_secret is None:
        cred = cred_resp.get("credential")
        if cred is not None:
            if isinstance(cred, str):
                client_secret = cred
            elif isinstance(cred, dict):
                client_secret = cred.get("value")
            else:
                client_secret = str(cred)

    un = cred_resp.get("userName")
    if un is not None:
        if isinstance(un, str):
            account_name = un
        elif isinstance(un, dict):
            account_name = un.get("value")
        else:
            account_name = str(un)
    if account_name is None:
        account_name = cred_resp.get("accountName")

    if not client_secret:
        return None, account_name, {
            "error": "Password value is null/empty in checkout response",
            "detail": json.dumps(cred_resp),
        }

    return client_secret, account_name, cred_resp


def _extract_account_key(acct):
    """Extract the accountkey from a Saviynt account record."""
    for key in ("accountkey", "accountKey", "ACCOUNTKEY", "userAccountId"):
        val = acct.get(key)
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                pass
    return None


# ======================================================================
# OPTION 2 - SAVIYNT PAM CHECKOUT + GRAPH VALIDATION
# ======================================================================
def pull_from_saviynt(spn_name):
    """Authenticate to Saviynt, pull account info for the given SPN name,
    checkout credential from PAM vault, then validate against Microsoft Graph.

    The Application (Client) ID is discovered from customproperty41 on the
    Saviynt account -- no hardcoded client/object IDs required.
    """
    print(f"\n{SEP}")
    print("  Saviynt PAM Checkout -> Microsoft Graph  (automatic validation)")
    print(f"{SEP}")
    print(f"  Service Principal Name : {spn_name}")
    print(f"  Endpoint / Connection  : {SAVIYNT_ENDPOINT}")
    print(f"  Tenant                 : {TENANT_ID}")
    print(f"{SEP}\n")

    # -- Saviynt auth ---------------------------------------------------
    username = SAVIYNT_USERNAME
    password = SAVIYNT_PASSWORD

    if not username:
        username = input("  Saviynt username: ").strip()
    if not password:
        password = getpass.getpass("  Saviynt password: ").strip()

    print("[INFO] Authenticating to Saviynt ...")
    sav_token, refresh_token, auth_resp = saviynt_login(SAVIYNT_BASE_URL, username, password)
    if sav_token is None:
        print("[FAIL] Saviynt authentication failed.")
        print(json.dumps(auth_resp, indent=2))
        return

    print("[OK]   Saviynt access token acquired.")
    if refresh_token:
        print(f"       Refresh token:  {refresh_token[:20]}...")
    else:
        print("[WARN] No refresh token returned - LLT generation may fail.")
    print()

    # -- Pull account info ----------------------------------------------
    print(f"[INFO] Fetching account '{spn_name}' from endpoint '{SAVIYNT_ENDPOINT}' ...")
    acct_resp = saviynt_get_account(SAVIYNT_BASE_URL, sav_token,
                                     spn_name, SAVIYNT_ENDPOINT)

    if "error" in acct_resp:
        print("[FAIL] Could not retrieve account from Saviynt.")
        print(json.dumps(acct_resp, indent=2))
        return

    print(f"[OK]   Saviynt response received.\n")
    print(json.dumps(acct_resp, indent=2))
    print()

    # Parse accounts list
    accounts = (
        acct_resp if isinstance(acct_resp, list)
        else acct_resp.get("Accountdetails")
        or acct_resp.get("accountdetails")
        or acct_resp.get("accounts")
        or acct_resp.get("value")
        or []
    )
    if not accounts:
        print(f"[FAIL] No accounts returned from Saviynt for '{spn_name}'.")
        print(f"       Verify the account name exists on endpoint '{SAVIYNT_ENDPOINT}'.")
        print(json.dumps(acct_resp, indent=2))
        return

    acct = accounts[0] if isinstance(accounts, list) else accounts

    # If multiple accounts returned, find the one matching our target name
    if isinstance(accounts, list) and len(accounts) > 1:
        for a in accounts:
            aname = a.get("name", "") or a.get("displayName", "")
            if aname == spn_name:
                acct = a
                break
        else:
            print(f"[WARN] Multiple accounts returned but none matched '{spn_name}' exactly.")
            print(f"       Using first result: {acct.get('name', 'N/A')} (accountKey={acct.get('accountKey', 'N/A')})")

    # -- Display custom attributes --------------------------------------
    print(f"\n{SEP}")
    print(f"  Saviynt Account: {acct.get('name', spn_name)}")
    print(f"{SEP}")
    for attr_key, description in CUSTOM_ATTR_MAP.items():
        value = acct.get(attr_key, "N/A")
        print(f"  {description:<45s} ({attr_key}): {value}")
    print(f"{SEP}")

    # Extract client ID from customproperty41 (stored by the rotation connector)
    effective_client_id = acct.get("customproperty41") or ""
    sav_object_id       = acct.get("customproperty42") or ""

    if not effective_client_id or effective_client_id == "N/A":
        print(f"\n[FAIL] customproperty41 (Application/Client ID) is empty or missing.")
        print(f"       Cannot authenticate to Graph without a Client ID.")
        print(f"       Ensure the rotation connector has stored the Client ID on this account.")
        return

    print(f"\n[INFO] Resolved Client ID from Saviynt:  {effective_client_id}")
    if sav_object_id and sav_object_id != "N/A":
        print(f"       Resolved Object ID from Saviynt:  {sav_object_id}")

    # -- Silently grant Graph API permissions early (propagation time) --
    grant_graph_permissions(effective_client_id)

    # Resolve accountkey for checkout
    account_key = _extract_account_key(acct)
    if account_key:
        print(f"       Resolved accountkey from Saviynt:  {account_key}")
    else:
        print(f"\n[WARN] Could not resolve accountkey from account response.")
        print(f"       Available keys: {list(acct.keys())}")
        try:
            manual_key = input("  Enter accountkey manually (or press Enter to abort): ").strip()
            if not manual_key:
                print("[FAIL] Cannot proceed without accountkey.")
                return
            account_key = int(manual_key)
        except ValueError:
            print("[FAIL] Invalid accountkey.")
            return

    # -- PAUSE: let user review account info before checkout ------------
    print()
    input("  Press Enter to proceed with PAM credential checkout ...")
    print()

    # ==================================================================
    # PAM CREDENTIAL CHECKOUT
    # ==================================================================
    print(f"{SEP}")
    print("  PAM Credential Checkout")
    print(f"{SEP}")
    print(f"  Connection:   {SAVIYNT_CONNECTION}")
    print(f"  Endpoint:     {SAVIYNT_ENDPOINT}")
    print(f"  Account:      {acct.get('name', spn_name)}")
    print(f"  Account Key:  {account_key}")
    print(f"  Duration:     {PAM_CHECKOUT_DURATION} minutes")
    print(f"{SEP}\n")

    # Step A: Generate Long-Lasting Token (LLT)
    print("[INFO] Generating Long-Lasting Token (LLT) for vault checkout ...")
    print(f"       POST {SAVIYNT_BASE_URL}/ECM/oauth/access_token_withissuer")
    if not refresh_token:
        print("[FAIL] No refresh token available. Cannot generate LLT.")
        return

    llt_token, llt_resp = saviynt_generate_llt(SAVIYNT_BASE_URL, refresh_token, account_key)
    if llt_token is None:
        print("[FAIL] LLT generation failed.")
        print(json.dumps(llt_resp, indent=2))
        return

    print(f"[OK]   LLT acquired: {llt_token[:20]}...\n")

    # Step B: Checkout credential from vault
    print(f"[INFO] Checking out credential from Saviynt PAM vault ...")
    print(f"       POST {SAVIYNT_BASE_URL}/ECMv6/api/pam/account/checkout")
    print(f"       accountId={account_key}, duration={PAM_CHECKOUT_DURATION}\n")

    checkout_secret, checkout_acct_name, checkout_resp = saviynt_checkout_credential(
        SAVIYNT_BASE_URL, llt_token, account_key,
        duration=PAM_CHECKOUT_DURATION,
        max_attempts=PAM_MAX_POLL_ATTEMPTS,
        poll_interval=PAM_POLL_INTERVAL_SECS,
    )

    if checkout_secret is None:
        print("[FAIL] Credential checkout failed.")
        print(json.dumps(checkout_resp, indent=2))
        return

    preview_len = min(6, len(checkout_secret))
    masked_secret = checkout_secret[:preview_len] + "*" * max(0, len(checkout_secret) - preview_len)
    print(f"[OK]   Client secret retrieved from vault!")
    if checkout_acct_name:
        print(f"       Account Name:  {checkout_acct_name}")
    print(f"       Secret Length: {len(checkout_secret)} characters")
    print(f"       Secret:        {masked_secret}")

    # -- PAUSE: let user see checkout result before Graph calls ---------
    print()
    input("  Press Enter to proceed with Microsoft Graph validation ...")
    print()

    # ==================================================================
    # VALIDATE AGAINST MICROSOFT GRAPH
    # ==================================================================
    print(f"{SEP}")
    print("  Microsoft Graph Validation (using vault-retrieved secret)")
    print(f"{SEP}\n")

    print(f"[INFO] Authenticating to tenant: {TENANT_ID}")
    print(f"       Application (Client) ID:  {effective_client_id}")
    print(f"       Secret:                   {masked_secret}\n")

    token_resp = get_ms_access_token(TENANT_ID, effective_client_id, checkout_secret)
    if "error" in token_resp:
        print("[FAIL] Authentication failed with vault-retrieved credentials.")
        print(json.dumps(token_resp, indent=2))
        return

    access_token = token_resp["access_token"]
    print("[OK]   Authentication successful. Token acquired.")
    print(f"       Token type:  {token_resp.get('token_type', 'N/A')}")
    print(f"       Expires in:  {token_resp.get('expires_in', 'N/A')} seconds\n")

    # -- 1. List users (User.Read.All) -----------------------------------
    print("[INFO] Calling GET /v1.0/users ...")
    users_resp = call_graph(access_token, "users?$top=10&$select=id,displayName,userPrincipalName,mail,accountEnabled")
    if "error" in users_resp:
        print("[WARN] Could not retrieve users.")
        print(f"       {users_resp.get('error', '')}")
    else:
        users = users_resp.get("value", [])
        print(f"[OK]   {len(users)} user(s) returned (top 10).\n")
        if users:
            print(f"       {'#':<4s} {'Display Name':<30s} {'UPN':<40s} {'Enabled':<10s} {'Object ID'}")
            print(f"       {'-'*4:<4s} {'-'*30:<30s} {'-'*40:<40s} {'-'*10:<10s} {'-'*36}")
            for i, u in enumerate(users, 1):
                display = u.get("displayName", "N/A")
                upn     = u.get("userPrincipalName") or u.get("mail") or "N/A"
                enabled = str(u.get("accountEnabled", "N/A"))
                obj_id  = u.get("id", "N/A")
                print(f"       {i:<4d} {display:<30s} {upn:<40s} {enabled:<10s} {obj_id}")

    # -- 2. Group details (Group.Read.All) ------------------------------
    print(f"\n[INFO] Calling GET /v1.0/groups/{ENTRA_GROUP_OBJECT_ID} ...")
    group_ep = f"groups/{ENTRA_GROUP_OBJECT_ID}?$select=id,displayName,description,mail,mailEnabled,securityEnabled,createdDateTime,membershipRule"
    group_resp = call_graph(access_token, group_ep)
    if "error" in group_resp:
        print(f"[WARN] Could not retrieve group details.")
        print(f"       {group_resp.get('error', '')}")
    else:
        print(f"[OK]   Group details retrieved.\n")
        print(f"       Display Name:     {group_resp.get('displayName', 'N/A')}")
        print(f"       Description:      {group_resp.get('description', 'N/A')}")
        print(f"       Mail:             {group_resp.get('mail', 'N/A')}")
        print(f"       Security Enabled: {group_resp.get('securityEnabled', 'N/A')}")
        print(f"       Mail Enabled:     {group_resp.get('mailEnabled', 'N/A')}")
        created = group_resp.get("createdDateTime", "N/A")
        if created and created != "N/A":
            created = created.split("T")[0]
        print(f"       Created:          {created}")
        membership_rule = group_resp.get("membershipRule")
        if membership_rule:
            print(f"       Membership Rule:  {membership_rule}")

    # -- 3. Group members (Group.Read.All) ------------------------------
    list_group_members(access_token, ENTRA_GROUP_OBJECT_ID, ENTRA_GROUP_NAME)

    # -- Optional: revoke temporarily granted permissions ---------------
    # Uncomment the next line to clean up permissions after validation:
    # revoke_graph_permissions(effective_client_id, granted_ids)

    print(f"\n{SEP}")
    print("  RESULT: Credential is VALID")
    print(f"{SEP}\n")


# ======================================================================
# MAIN
# ======================================================================
def main():
    print(f"\n{'=' * 64}")
    print("  Azure Entra ID - Client Secret Validator")
    print(f"  Saviynt PAM Checkout -> Microsoft Graph")
    print(f"{'=' * 64}")
    print(f"  Directory (Tenant) ID   : {TENANT_ID}")
    print(f"  Saviynt Endpoint        : {SAVIYNT_ENDPOINT}")
    print(f"  Entra Group             : {ENTRA_GROUP_NAME} ({ENTRA_GROUP_OBJECT_ID})")
    print(f"{'=' * 64}\n")

    spn_name = input("  Enter Service Principal Name: ").strip()
    if not spn_name:
        print("[ERROR] Service Principal Name is required.")
        return

    pull_from_saviynt(spn_name)


if __name__ == "__main__":
    main()