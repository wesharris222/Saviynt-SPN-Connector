[README2.md](https://github.com/user-attachments/files/28117668/README2.md)
# 🔐 Azure SPN Credential Lifecycle (Saviynt PAM)

> A Saviynt EIC REST connector configuration that automates **discovery** and **credential rotation** for Azure Entra ID service principals (SPNs), with rotated secrets vaulted in **HashiCorp Vault**.

---

## 🏗️ Architecture

The flow spans **two Saviynt endpoints**:

| Endpoint | Role | PAM-Managed? |
| :--- | :--- | :---: |
| **Discovery** | Reconciles SPNs from Entra ID to build an inventory. Every matching SPN gets an account record here. | ❌ Informational only |
| **Vault** | Holds the mirror accounts that PAM actively manages — rotates, vaults, and brokers for checkout. | ✅ Yes |

Separating the **discovery plane** from the **active-management plane** lets you govern *which* SPNs get vaulted without polluting the vault with every SPN in the directory.

---

## ⚙️ How It Works

### 1. Discovery — `ImportAccountEntJSON`

Queries the **Microsoft Graph API** for applications whose `displayName` matches a configurable name filter, pulling back `id`, `appId`, `displayName`, and `passwordCredentials`.

Each matching SPN is imported as a Saviynt account on the **discovery endpoint**, where:

- The Entra `appId` and object `id` are mapped to `customproperty41` / `customproperty42`.
- The account type is forced to `FIREFIGHTERID` via `#CONST#` syntax — so accounts land as PAM-managed firefighter credentials.

### 2. Rotation — `ChangePassJSON`

On rotation, the connector runs an **eight-step `callOrder`**:

| # | Step | Description |
| :---: | :--- | :--- |
| 1 | **CreateMirrorAccount** / **PAMEnableMirror** | Creates a mirror account on the vault endpoint and applies the PAM `accountConfig` so it surfaces as a checkout-able credential. |
| 2 | **GetCurrentCreds** | Reads the SPN's existing `passwordCredentials` from Graph (keeps the old `keyId` for later cleanup). |
| 3 | **AddSecret** | Calls Graph `addPassword` to mint a new client secret with a timestamped display name. |
| 4 | **StoreToVault** / **ReadFromVault** | Writes the new secret into HashiCorp Vault under a per-account path, then reads it back to confirm the write. |
| 5 | **StoreAttributes** | Updates the Saviynt account with the current Entra identifiers. |
| 6 | **RemoveOldSecret** | Deletes the previous client secret from the SPN via Graph `removePassword`, leaving only the freshly vaulted credential active. |

### 3. Connections — `ConnectionJSON`

Defines two **active** auth contexts:

- **`userAuth`** — OAuth2 client-credentials against Microsoft Graph for all Azure operations.
- **`savAuth`** — Saviynt API login for the account create/update calls.

> ℹ️ A third context, **`savAuthInternal`**, is included but **unused**. It points at the internal Saviynt API URL and is left in place in case an internal-routing variant is needed later.

---

## ⚠️ Known Issues

> **Check the repo's [Issues page](../../issues) before relying on this in production.**

There is a known consistency problem with the **`RemoveOldSecret`** step: because of Azure Entra ID concurrency/replication controls, generating a new secret and removing the old one in rapid succession can fail (e.g. a `409 Conflict`) if Entra hasn't yet propagated the new credential.

See the issue thread for the **padding-delay workaround**.

---

## 🚀 Setup

Replace all `<PLACEHOLDER>` values before loading the configs into the connection:

- [ ] Tenant ID
- [ ] Client ID / Client Secret
- [ ] Saviynt tenant URL and credentials
- [ ] Vault security system / endpoint
- [ ] Vault secret path and token
- [ ] SPN name filter

---

## 📂 Files

| File | Purpose |
| :--- | :--- |
| `SPN_Lifecycle_ConnectionJSON-clean.json` | Auth contexts for Microsoft Graph and Saviynt APIs. |
| `SPN_Lifecycle_ImportAccountEntJSON-clean.json` | SPN discovery and import logic. |
| `SPN_Lifecycle_ChangePassJSON-clean.json` | Eight-step credential rotation workflow. |
