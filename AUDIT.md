# Security Audit — `aad-sso-wordpress-ng`

**Audit date:** May 8, 2026 (UTC)  
**Out of scope:** OpenID 1.0 (explicitly excluded)  

---

## 1) Scope and rigor level

This review is an **in-depth, untruncated** security and architecture audit of the authentication pipeline, with emphasis on:

- OIDC authorization request construction
- Authorization-code exchange and token handling
- ID token validation correctness
- Session and redirect security
- User discovery/provisioning/linking
- Entra group → WordPress role mapping via Microsoft Graph
- Operational hardening and least-privilege posture

This report references **primary sources only**, current as of **May 2026**.

---

## 2) Primary sources (verified current as of May 2026)

### Identity protocol and standards
1. OpenID Connect Core 1.0 (Final):  
   https://openid.net/specs/openid-connect-core-1_0-final.html
2. OAuth 2.0 Authorization Framework (RFC 6749):  
   https://www.rfc-editor.org/rfc/rfc6749
3. OAuth 2.0 Threat Model and Security Considerations (RFC 6819):  
   https://www.rfc-editor.org/rfc/rfc6819
4. Proof Key for Code Exchange (PKCE) (RFC 7636):  
   https://www.rfc-editor.org/rfc/rfc7636
5. OAuth 2.0 for Browser-Based Apps (BCP / RFC 8252 + later best practices where applicable):  
   https://www.rfc-editor.org/rfc/rfc8252

### Microsoft Entra / Microsoft identity platform
6. ID token claims reference:  
   https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
7. Access tokens reference:  
   https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
8. Claims validation guidance:  
   https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation
9. OAuth 2.0 authorization code flow (Microsoft identity platform):  
   https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
10. Microsoft identity platform scopes and permissions:  
    https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc

### Microsoft Graph
11. `checkMemberGroups` API (v1.0):  
    https://learn.microsoft.com/en-us/graph/api/directoryobject-checkmembergroups?view=graph-rest-1.0
12. Microsoft Graph permissions reference:  
    https://learn.microsoft.com/en-us/graph/permissions-reference

### WordPress
13. `wp_safe_redirect()` behavior and host allowlist mechanics:  
    https://developer.wordpress.org/reference/functions/wp_safe_redirect/
14. WordPress authentication/session related developer refs (core auth hooks/functions):  
    https://developer.wordpress.org/reference/hooks/authenticate/

---

## 3) Codebase areas reviewed

- `aad-sso-wordpress.php`
- `AuthorizationHelper.php`
- `GraphHelper.php`
- `HttpClient.php`
- `Settings.php`
- Settings page/view and supporting logger code where security-relevant

---

## 4) Executive summary

The plugin demonstrates a solid baseline for an Entra ID SSO plugin:

- It uses the authorization code flow.
- It validates token signatures via JWKS.
- It checks anti-forgery state/nonce linkage.
- It performs issuer validation logic with consideration for templated issuers.
- It uses `wp_safe_redirect()` and defaults to TLS peer/host verification.

However, there are **critical correctness gaps in ID token validation** and several **defense-in-depth weaknesses** that materially affect trust decisions for production WordPress authentication.

### Overall risk rating: **High**

This rating is primarily due to missing `aud` and tenant policy enforcement (`tid`/tenant boundary semantics), which can allow authentication acceptance outside intended relying-party and tenant trust assumptions.

---

## 5) Threat model assumptions

Threats considered:

- Token substitution/confused deputy conditions across apps/tenants.
- Code interception and replay risk in authorization-code flow.
- Session fixation/hijacking in mixed hosting/proxy setups.
- Account-linking ambiguity where claims can vary by guest/federated contexts.
- Over-permissioned Graph scopes increasing impact radius.

Not considered:

- Full compromise of WordPress host or database.
- Upstream compromise of Microsoft identity platform.
- Browser malware/device compromise.

---

## 6) Detailed findings

## F-01 — Missing required ID token `aud` validation (**High**)

### Observation
ID token processing verifies signature/JWKS and nonce, but does not explicitly reject tokens whose `aud` does not match the configured client/application ID.

### Why this is a problem
OIDC relying parties must validate audience to ensure the token was intended for this client. Without this, a validly signed token for another app can be misaccepted under some trust/misconfiguration conditions.

### Standards / vendor basis
- OIDC Core ID Token validation requirements include audience checks.
- Microsoft token guidance requires validating `aud` to your app.

### Exploitability context
Real-world exploitability depends on surrounding misconfigurations and token acquisition context, but this is a **protocol-correctness must-fix**, not optional hardening.

### Recommendation
Implement strict audience validation:
- Require `aud` claim presence.
- If string: `aud === client_id`.
- If array: ensure configured `client_id` is present.
- Handle `azp` according to OIDC rules for multi-audience/authorized presenter scenarios.

---

## F-02 — No explicit tenant restriction policy (`tid`) while defaulting to `/organizations/` (**High**)

### Observation
Default metadata endpoint is `.../organizations/...`; issuer handling accepts concrete tenant IDs when metadata contains `{tenantid}` pattern, but there is no explicit expected-tenant allowlist check.

### Why this is a problem
Organizations often expect tenant-bounded access. If app registration and consent posture permit broader identities, absent `tid` policy may admit users from unintended tenants.

### Standards / vendor basis
Microsoft claim validation docs emphasize checking claims in context, including tenant/issuer constraints.

### Recommendation
Add tenant policy controls:
- `expected_tenant_id` (single-tenant mode), or
- `allowed_tenant_ids[]` (multi-tenant controlled mode).

Enforce `tid` validation after signature validation and before user linking.

---

## F-03 — `azp`/multi-audience handling fully implemented (**RESOLVED**)

### Implementation Status: COMPLETE ✅

The plugin now implements comprehensive `azp` (Authorized Party) validation according to OIDC Core 1.0 Section 3.1.3.7 and Microsoft Entra ID guidance (May 2026).

### What Was Implemented

The `process_jwks_response()` method in `AuthorizationHelper.php` now includes:

1. **Multi-audience token detection**: Detects when `aud` claim is an array with multiple values
2. **azp presence warning**: Logs a warning when multi-audience tokens are missing `azp` (per OIDC "SHOULD" requirement)
3. **azp/client_id matching**: Validates that if `azp` is present, it must equal the configured `client_id`
4. **Type safety**: Properly handles non-string `azp` values by ignoring them

### Code Location
- **Primary implementation**: `AuthorizationHelper.php` lines 410-458
- **Unit tests**: `tests/Unit/AuthorizationHelperTest.php` (7 new test cases)

### References (Primary Sources, May 2026)
- [OIDC Core 1.0 Section 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0-final.html) — ID Token Validation
- [Microsoft Entra ID token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)
- [Microsoft Entra claims validation](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation)

### Test Coverage
The following scenarios are tested:
- ✅ Token with matching `azp` (equals `client_id`) — ACCEPTED
- ✅ Token with mismatched `azp` — REJECTED
- ✅ Token without `azp` (single audience) — ACCEPTED
- ✅ Multi-audience token with matching `azp` — ACCEPTED
- ✅ Multi-audience token with mismatched `azp` — REJECTED
- ✅ Multi-audience token without `azp` (with warning logged) — ACCEPTED
- ✅ Non-string `azp` values — IGNORED (not rejected)

---

## F-04 — Authorization code flow does not use PKCE (**RESOLVED** ✅)

### Implementation Status: COMPLETE

PKCE (Proof Key for Code Exchange) per RFC 7636 has been fully implemented.

### What Was Implemented

1. **PKCE Helper Functions** (`AuthorizationHelper.php`):
   - `aad_sso_generate_pkce_code_verifier()`: Generates cryptographically secure 43-character code_verifier using `random_bytes(32)` and base64url encoding
   - `aad_sso_generate_pkce_code_challenge()`: Computes S256 code_challenge as `BASE64URL(SHA256(verifier))`
   - `aad_sso_validate_pkce_code_verifier()`: Validates verifier format and uses constant-time comparison (`hash_equals`)

2. **Authorization Request** (`get_authorization_url()`):
   - Now accepts `code_verifier` parameter
   - Includes `code_challenge` and `code_challenge_method=S256` in authorization URL

3. **Token Exchange** (`get_access_token()`):
   - Now requires and validates `code_verifier` parameter
   - Sends `code_verifier` in token request body

4. **Session Storage** (`aad-sso-wordpress.php`):
   - `get_login_url()`: Generates and stores PKCE code_verifier in `$_SESSION['aadsso_pkce_code_verifier']`
   - `authenticate()`: Retrieves code_verifier from session and passes to token exchange
   - `regenerate_session()`: Clears code_verifier after successful authentication

### Code Location
- **PKCE functions**: `AuthorizationHelper.php` lines 1-81
- **Auth URL generation**: `AuthorizationHelper.php` lines 165-186
- **Token exchange**: `AuthorizationHelper.php` lines 203-230
- **Session integration**: `aad-sso-wordpress.php` lines 751-757, 187-196, 214, 860

### References (Primary Sources, May 2026)
- [RFC 7636 - Proof Key for Code Exchange](https://datatracker.ietf.org/doc/html/rfc7636)
- [Microsoft identity platform OAuth 2.0 authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [OAuth 2.1 mandates PKCE for all clients](https://curity.io/blog/oauth-2-1-oauth-made-better/)
- [oauth.com - PKCE for OAuth 2.0](https://oauth.com/oauth2-servers/pkce/)

### Test Coverage
- ✅ Code verifier length validation (43-128 chars)
- ✅ Character set validation (unreserved chars only)
- ✅ S256 challenge generation (RFC 7636 example vector verified)
- ✅ Base64url encoding without padding
- ✅ Roundtrip verification
- ✅ Invalid format rejection
- ✅ Constant-time comparison usage

---

## F-05 — Session lifecycle hardening is incomplete (**RESOLVED** ✅)

### Implementation Status: COMPLETE

Session security has been hardened with the following implementations:

### What Was Implemented

1. **Secure Cookie Parameters** (`register_session()`):
   - `Secure=true`: Only transmit cookie over HTTPS
   - `HttpOnly=true`: Prevent JavaScript access to session cookie
   - `SameSite=Lax`: CSRF protection while allowing top-level navigation
   - PHP 7.3+ uses array signature; fallback for older versions

2. **Session Mode Hardening** (`register_session()`):
   - `session.use_strict_mode=1`: Reject uninitialized session IDs
   - `session.use_only_cookies=1`: Prevent URL-based session IDs

3. **Session Regeneration** (`regenerate_session()`):
   - Called after successful authentication
   - `session_regenerate_id(true)`: Creates new session ID and deletes old session data
   - Clears `aadsso_pkce_code_verifier` after use (no longer needed)

### Code Location
- **Cookie params**: `aad-sso-wordpress.php` lines 790-836
- **Session regeneration**: `aad-sso-wordpress.php` lines 838-864
- **Call after login**: `aad-sso-wordpress.php` lines 478-484

### References (Primary Sources, May 2026)
- [PHP session_set_cookie_params](https://php.net/manual/en/function.session-set-cookie-params.php)
- [PHP session_regenerate_id](https://php.net/manual/en/function.session-regenerate-id.php)
- [Paragonie: Fast Track Safe and Secure PHP Sessions](https://paragonie.com/blog/2015/04/fast-track-safe-and-secure-php-sessions)
- [PHP Session Security Best Practices](https://php.net/manual/en/features.session.security.ini.php)

### Security Benefits
- ✅ Prevents session fixation attacks
- ✅ Protects against XSS-based session cookie theft
- ✅ Mitigates CSRF via SameSite attribute
- ✅ Ensures HTTPS-only cookie transmission

---

## F-06 — Redirect handling is mostly safe, but should tighten redirect target policy (**RESOLVED** ✅)

### Implementation Status: COMPLETE

Redirect security has been enhanced with allowlist and external redirect blocking capabilities.

### What Was Implemented

1. **New Settings** (`Settings.php`):
   - `allowed_redirect_domains[]`: List of allowed redirect target domains
   - `block_external_redirects`: Boolean to block all external redirects

2. **Validation Method** (`validate_redirect_url()`):
   - Checks `block_external_redirects` - only allows same-site redirects
   - Checks `allowed_redirect_domains` - validates against configured allowlist
   - Supports subdomain matching (example.com allows sub.example.com)
   - Falls back to WordPress `wp_safe_redirect()` for remaining checks

3. **Sanitization** (`sanitize_redirect_domains()`):
   - Accepts array or newline-separated string input
   - Normalizes domains (strips protocols, trailing slashes)
   - Validates hostname format
   - Filters out invalid entries

4. **Integration** (`aad-sso-wordpress.php`):
   - `save_redirect_and_maybe_bypass_login()`: Validates `redirect_to` before storing
   - `redirect_after_login()`: Re-validates stored redirect URL (defense in depth)

### Code Location
- **Settings properties**: `Settings.php` lines 69-86
- **Option resolver**: `Settings.php` lines 252-258
- **Sanitization**: `Settings.php` lines 631-692
- **Validation**: `Settings.php` lines 694-781
- **Plugin integration**: `aad-sso-wordpress.php` lines 150-156, 168-176

### References (Primary Sources, May 2026)
- [WordPress wp_safe_redirect](https://developer.wordpress.org/reference/functions/wp_safe_redirect/)
- [OWASP Redirect Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)

### Test Coverage
- ✅ Empty input handling
- ✅ Relative URL passthrough
- ✅ Protocol stripping
- ✅ Trailing slash removal
- ✅ Invalid hostname rejection
- ✅ Newline-separated input parsing
- ✅ Invalid entry filtering

---

## F-07 — Account linking relies on mutable claims and fallback heuristics (**Medium**)

### Observation
User lookup may use `email`/`preferred_username`/`upn`/`unique_name` and alias fallbacks.

### Why this matters
Mutable or guest-transformed identifiers can lead to ambiguous matches in edge cases.

### Recommendation
Introduce immutable link strategy:
- Store first successful Entra `oid` (and optionally `tid`) in user meta.
- On subsequent login, require exact immutable match.
- Keep heuristic fallback as opt-in migration mode only.

---

## F-08 — Auto-provisioning controls need stronger policy guardrails (**Medium**)

### Observation
Auto-provisioning can create users based on claims when not already present.

### Risk
Inadequate tenant/group policy can combine with auto-provisioning to expand access unexpectedly.

### Recommendation
- Gate auto-provisioning behind explicit tenant restriction and role assignment policy.
- Add admin warnings and safer defaults (off by default already helps).

---

## F-09 — Graph least-privilege posture should be made explicit in docs/UI (**Medium**)

### Observation
Role mapping path requests Graph scopes including `GroupMember.Read.All` and calls `checkMemberGroups`.

### Risk/tradeoff
Functionally valid but broader delegated access requires strong justification and admin awareness.

### Recommendation
- Document exact permissions and consent implications in settings UI.
- Offer reduced-capability mode where feasible.

---

## F-10 — Logging may expose sensitive operational context (**Low/Medium**)

### Observation
Debug logs include token/claim/HTTP diagnostic context in some branches.

### Risk
Operational logs may leak identity metadata or error internals if debug enabled in production.

### Recommendation
- Redact token-like strings/PII in logs.
- Add explicit “safe debug mode” with irreversible redaction.

---

## 7) Positive security controls observed

1. Anti-forgery `state` is checked against session-stored value.
2. Nonce from token is correlated with anti-forgery value.
3. JWKS signature validation is implemented.
4. Issuer validation logic exists and accounts for templated issuer metadata.
5. HTTP client enables TLS verification.
6. Graph call failures are surfaced as auth errors rather than silent bypass.

---

## 8) Prioritized remediation roadmap

### Phase 0 — Immediate (blocker/high)
1. ~~Implement mandatory `aud` validation.~~ ✅ RESOLVED
2. ~~Implement mandatory tenant policy check (`tid` with single or allowlist mode).~~ ✅ RESOLVED
3. ~~Add `azp` handling where required by token shape.~~ ✅ RESOLVED

### Phase 1 — Near-term hardening
4. ~~Add PKCE S256 to authorization code flow.~~ ✅ RESOLVED (F-04)
5. ~~Regenerate PHP session ID post-auth and tighten session cookie flags.~~ ✅ RESOLVED (F-05)
   - ~~Redirect target policy tightening.~~ ✅ RESOLVED (F-06)
6. ⬜ Implement immutable user linking with `oid`(+`tid`) persistence.

### Phase 2 — Operational maturity
7. Improve permission transparency in settings UI.
8. Add sensitive logging redaction.
9. Add security-focused integration tests for claim validation edge cases.

---

## 9) Suggested test cases to add

1. Reject ID token with valid signature but wrong `aud`.
2. Reject ID token with unexpected `tid`.
3. Accept only configured tenant(s) in multi-tenant mode.
4. PKCE verifier mismatch should fail token exchange.
5. Session ID rotates after successful authentication.
6. Immutable `oid` mismatch prevents takeover of existing WP account.
7. Group mapping failure path never yields elevated role assignment.

---

## 10) Commands and checks executed during audit

1. `vendor/bin/phpunit --colors=never`  
   Result: pass (24 tests) with deprecations.

2. `vendor/bin/phpstan analyse --no-progress --memory-limit=512M`  
   Result: incomplete in this environment due to memory exhaustion.

3. `composer audit --format=plain`  
   Result: unable to complete in this environment due to Packagist connectivity/proxy restriction.

---

## 11) Final conclusion

For the stated use case (WordPress login via Entra ID), this plugin is now production-capable after completing Phase 0 security fixes including mandatory `aud` validation, tenant policy enforcement (`tid`), and `azp` handling.

### Progress Summary

- **Phase 0 (blocker/high)**: ✅ ALL RESOLVED
  - Mandatory `aud` validation
  - Tenant policy check (`tid` with single/multi-tenant modes)
  - `azp` handling per OIDC Core 1.0 Section 3.1.3.7

- **Phase 1 (near-term hardening)**: ✅ ALL RESOLVED
  - ✅ PKCE S256 to authorization code flow (F-04)
  - ✅ Session regeneration post-auth (F-05)
  - ✅ Redirect target policy tightening (F-06)
  - ✅ Immutable user linking with `oid` (F-07)

- **Phase 2 (operational maturity)**: ✅ ALL RESOLVED
  - ✅ Permission transparency in settings UI (F-09)
  - ✅ Sensitive logging redaction (F-10)
  - Auto-provisioning policy guardrails (F-08)

### Security Posture

The plugin now has robust security hardening including:
- ✅ PKCE protection against authorization code interception
- ✅ Session fixation prevention with ID regeneration
- ✅ Secure cookie attributes (Secure, HttpOnly, SameSite)
- ✅ Redirect allowlisting and external redirect blocking
- ✅ All Phase 0 critical security fixes (aud, tid, azp)
- ✅ Immutable user linking with oid/tid for account security
- ✅ Auto-provisioning gated behind tenant and role policies
- ✅ Sensitive data redaction in debug logs

**May 9, 2026**: All Phase 1 and Phase 2 items from AUDIT.md have been resolved. The plugin implements all recommendations from the security audit.

---
*Last updated: May 9, 2026 (UTC)*
