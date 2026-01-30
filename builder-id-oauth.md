# AWS Builder ID OAuth (Device Code Flow) - Implementation Guide

## Overview

AWS Builder ID uses the **OAuth 2.0 Device Authorization Grant** (RFC 8628) for CLI/headless authentication. This flow allows users to authenticate on a separate device (browser) while the CLI polls for completion.

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────┐     ┌─────────────┐
│   CLI App   │────▶│  AWS OIDC Endpoint                   │────▶│   Browser   │
│             │     │  oidc.{region}.amazonaws.com         │     │  (User)     │
└─────────────┘     └──────────────────────────────────────┘     └─────────────┘
      │                           │
      │  1. Register Client       │
      │  2. Request Device Code   │
      │  3. Poll for Token        │
      │                           │
      ▼                           ▼
┌─────────────┐           ┌─────────────┐
│ Credentials │           │   Token     │
│   Storage   │◀──────────│  Response   │
└─────────────┘           └─────────────┘
```

---

## Step 1: Register OIDC Client

**Endpoint:** `POST https://oidc.{region}.amazonaws.com/client/register`

**Request:**
```json
{
  "clientName": "Kiro IDE",
  "clientType": "public",
  "scopes": [
    "codewhisperer:completions",
    "codewhisperer:analysis",
    "codewhisperer:conversations"
  ]
}
```

**Headers:**
```
Content-Type: application/json
User-Agent: KiroIDE
```

**Response:**
```json
{
  "clientId": "xxxxxxxxxxxxxxxxxxxxxxxx",
  "clientSecret": "xxxxxxxxxxxxxxxxxxxxxxxx"
}
```

**Notes:**
- Client registration is per-device; store `clientId` and `clientSecret` with credentials
- Region is typically `us-east-1`

---

## Step 2: Request Device Authorization

**Endpoint:** `POST https://oidc.{region}.amazonaws.com/device_authorization`

**Request:**
```json
{
  "clientId": "{clientId from Step 1}",
  "clientSecret": "{clientSecret from Step 1}",
  "startUrl": "https://view.awsapps.com/start"
}
```

**Response:**
```json
{
  "deviceCode": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "userCode": "ABCD-EFGH",
  "verificationUri": "https://device.sso.us-east-1.amazonaws.com/",
  "verificationUriComplete": "https://device.sso.us-east-1.amazonaws.com/?user_code=ABCD-EFGH",
  "expiresIn": 300,
  "interval": 5
}
```

**User Interaction:**
1. Display `verificationUriComplete` to user (or `verificationUri` + `userCode`)
2. User opens URL in browser and completes AWS Builder ID sign-in
3. CLI polls for token completion

---

## Step 3: Poll for Token

**Endpoint:** `POST https://oidc.{region}.amazonaws.com/token`

**Request:**
```json
{
  "clientId": "{clientId}",
  "clientSecret": "{clientSecret}",
  "deviceCode": "{deviceCode from Step 2}",
  "grantType": "urn:ietf:params:oauth:grant-type:device_code"
}
```

**Polling Logic:**
```
interval = device_auth.interval (default 5 seconds)
timeout = device_auth.expiresIn (default 300 seconds)

LOOP until timeout:
    WAIT interval seconds
    POST /token request
    
    IF success (200):
        RETURN token_response
    
    IF error response:
        IF error == "authorization_pending":
            CONTINUE polling (user hasn't authorized yet)
        
        IF error == "slow_down":
            interval += 5 seconds
            CONTINUE polling
        
        ELSE:
            FAIL with error
```

**Success Response:**
```json
{
  "accessToken": "aoaAAAAAGlfTyA8C4c...",
  "refreshToken": "aorABBBBBBBBBBBBBBB...",
  "expiresIn": 3600
}
```

**Error Response:**
```json
{
  "error": "authorization_pending",
  "errorDescription": "User has not yet authorized"
}
```

---

## Step 4: Store Credentials

**Credential Structure:**
```json
{
  "accessToken": "aoaA...",
  "refreshToken": "aorA...",
  "clientId": "xxx",
  "clientSecret": "xxx",
  "expiresAt": "2026-01-28T10:30:00.000Z",
  "authMethod": "builder-id",
  "idcRegion": "us-east-1",
  "status": "healthy",
  "recoveryTime": null
}
```

**Storage Recommendations:**
- Store as JSON file (e.g., `~/.your-app/credentials.json`)
- Support multiple credentials (pool) for rotation/failover
- Use atomic writes (write to temp file, then rename) to prevent corruption
- Calculate `expiresAt` as: `now + expiresIn seconds`

---

## Step 5: Token Refresh

When `accessToken` expires (or within 30-minute buffer), refresh using `refreshToken`.

**Endpoint:** `POST https://oidc.{region}.amazonaws.com/token`

**Request:**
```json
{
  "refreshToken": "{refreshToken}",
  "clientId": "{clientId}",
  "clientSecret": "{clientSecret}",
  "grantType": "refresh_token"
}
```

**Response:**
```json
{
  "accessToken": "aoaA...(new)...",
  "refreshToken": "aorA...(new)...",
  "expiresIn": 3600
}
```

**Important:** Both `accessToken` AND `refreshToken` are replaced on refresh. Store both new values.

---

## Step 6: Using the Token (Kiro API)

**Endpoint:** `POST https://q.{region}.amazonaws.com/generateAssistantResponse`

**Required Headers:**
```
Authorization: Bearer {accessToken}
Content-Type: application/json
Accept: application/json
User-Agent: aws-sdk-js/1.0.0 ua/2.1 os/macos lang/js api/codewhispererruntime#1.0.0 m/E KiroIDE-{version}-{machineId}
x-amzn-kiro-agent-mode: vibe
amz-sdk-invocation-id: {uuid}
amz-sdk-request: attempt=1; max=1
x-amz-user-agent: aws-sdk-js/1.0.0 KiroIDE-{version}-{machineId}
```

**Machine ID Generation:**
```python
import hashlib
machine_id = hashlib.sha256(client_id.encode()).hexdigest()[:32]
```

---

## Error Handling

| HTTP Status | Meaning | Action |
|-------------|---------|--------|
| `401` | Token invalid/expired | Refresh token, retry |
| `402` | Monthly quota exhausted | Mark unhealthy, set recovery to 1st of next month |
| `403` + "suspended" | Account suspended | Mark unhealthy permanently |
| `403` (other) | Temporary auth issue | Refresh token, retry |

**Credential Status State Machine:**
```
Healthy ──┬── 401/403 ──▶ NeedRefresh ──▶ (auto-refresh) ──▶ Healthy
          │
          ├── 402 ──▶ Unhealthy (recovery_time = 1st of next month)
          │
          └── 403 + "suspended" ──▶ Unhealthy (permanent)
```

---

## Constants

```
# Endpoints
OIDC_ENDPOINT = https://oidc.{region}.amazonaws.com
KIRO_ENDPOINT = https://q.{region}.amazonaws.com/generateAssistantResponse

# Default region
DEFAULT_REGION = us-east-1

# Start URL (Builder ID)
DEFAULT_START_URL = https://view.awsapps.com/start

# Timeouts
OIDC_TIMEOUT = 15 seconds
REQUEST_TIMEOUT = 120 seconds
AUTH_TIMEOUT = 300 seconds (from expiresIn)

# Token expiration buffer
EXPIRATION_BUFFER = 30 minutes

# Kiro version (for User-Agent)
KIRO_VERSION = 0.8.140
```

---

## Pseudocode Implementation

```python
async def login(start_url: str = DEFAULT_START_URL) -> Credential:
    # Step 1: Register OIDC client
    client_reg = await http_post(
        f"{OIDC_ENDPOINT}/client/register",
        json={
            "clientName": "Kiro IDE",
            "clientType": "public",
            "scopes": [
                "codewhisperer:completions",
                "codewhisperer:analysis",
                "codewhisperer:conversations"
            ]
        },
        headers={"User-Agent": "KiroIDE"}
    )
    
    # Step 2: Request device authorization
    device_auth = await http_post(
        f"{OIDC_ENDPOINT}/device_authorization",
        json={
            "clientId": client_reg.client_id,
            "clientSecret": client_reg.client_secret,
            "startUrl": start_url
        }
    )
    
    # Step 3: Display to user
    print(f"Visit: {device_auth.verification_uri_complete}")
    print(f"Code: {device_auth.user_code}")
    
    # Step 4: Poll for token
    interval = device_auth.interval
    deadline = time.now() + device_auth.expires_in
    
    while time.now() < deadline:
        await sleep(interval)
        
        response = await http_post(
            f"{OIDC_ENDPOINT}/token",
            json={
                "clientId": client_reg.client_id,
                "clientSecret": client_reg.client_secret,
                "deviceCode": device_auth.device_code,
                "grantType": "urn:ietf:params:oauth:grant-type:device_code"
            }
        )
        
        if response.ok:
            token = response.json()
            break
        
        error = response.json()
        if error.error == "authorization_pending":
            continue
        elif error.error == "slow_down":
            interval += 5
            continue
        else:
            raise AuthError(error.error)
    
    # Step 5: Create and store credential
    credential = Credential(
        access_token=token.access_token,
        refresh_token=token.refresh_token,
        client_id=client_reg.client_id,
        client_secret=client_reg.client_secret,
        expires_at=datetime.now() + timedelta(seconds=token.expires_in),
        auth_method="builder-id",
        idc_region="us-east-1",
        status="healthy"
    )
    
    save_credential(credential)
    return credential


async def refresh_token(credential: Credential) -> Credential:
    response = await http_post(
        f"https://oidc.{credential.idc_region}.amazonaws.com/token",
        json={
            "refreshToken": credential.refresh_token,
            "clientId": credential.client_id,
            "clientSecret": credential.client_secret,
            "grantType": "refresh_token"
        }
    )
    
    token = response.json()
    
    return Credential(
        access_token=token.access_token,
        refresh_token=token.refresh_token,  # NEW refresh token!
        client_id=credential.client_id,
        client_secret=credential.client_secret,
        expires_at=datetime.now() + timedelta(seconds=token.expires_in),
        auth_method=credential.auth_method,
        idc_region=credential.idc_region,
        status="healthy"
    )


def is_expired(credential: Credential) -> bool:
    """Check if credential is expired or will expire within 30 minutes."""
    buffer = timedelta(minutes=30)
    return credential.expires_at <= datetime.now() + buffer
```

---

## Key Implementation Notes

1. **All JSON fields use camelCase** - Both requests and responses use camelCase (e.g., `clientId`, not `client_id`)

2. **30-minute expiration buffer** - Consider tokens expired 30 minutes before actual expiration to prevent mid-request failures

3. **Store client credentials** - `clientId` and `clientSecret` from registration must be stored with the token for refresh

4. **Both tokens refresh** - When refreshing, you get a NEW `refreshToken` as well as a new `accessToken`

5. **Credential deduplication** - When re-logging in, update existing credential if `clientId` matches rather than creating duplicates

6. **Atomic file writes** - Write to temp file then rename to prevent corruption on crash

7. **402 recovery** - Payment errors (quota exhausted) recover on the 1st of the next month

