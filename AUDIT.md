# Enterprise Readiness Audit

**Audited project:** Single Sign-on with Microsoft Entra ID for WordPress

**Audit date:** 24 September 2026 (UTC)
**Target baseline:** WordPress 7.1.2, supported stable PHP releases, a locked current Composer dependency set, and current Microsoft Entra ID / Microsoft Graph behavior.

## Executive conclusion

This release **must not be represented as 100% compatible or enterprise-ready**. Static analysis and unit tests are useful, but they do not establish compatibility with WordPress 7.1.2 or a live Entra tenant. The release also has supply-chain reproducibility defects: no committed Composer lock file and a committed `vendor/` tree that does not satisfy several declared dependency constraints.

Certification requires the prioritized work below and a repeatable, passing test matrix against the exact target versions. Upstream WordPress, PHP, Composer advisory, and Microsoft documentation endpoints could not be queried from the audit environment because its outbound proxy returned HTTP 403; all “current as of” assertions must therefore be re-verified during release certification.

## Scope and audit evidence

Reviewed:

- Plugin runtime, settings, login, user-linking, Graph, HTTP, logging, and uninstall code.
- Plugin metadata, both README formats, Composer manifest and bundled dependency metadata.
- Unit-test bootstrap, CI workflow, and release/activation paths.

Checks completed:

- PHP syntax validation for project files: pass.
- PHPUnit: 78 tests / 149 assertions passed, but with 36 deprecations, 16 notices, and one skipped test.
- PHPStan: pass.
- PHP-CS-Fixer dry run: pass, with a warning that the local runtime was PHP 8.5.7-dev rather than the project minimum PHP 8.4.
- Composer manifest validation: pass.
- Composer security audit: blocked by the environment proxy.

## Compatibility status

| Target | Status | Reason |
|---|---|---|
| WordPress 7.1.2 | **Fail / unverified** | Metadata says tested only through 6.9.4; no pinned 7.1.2 integration test exists. |
| PHP 8.4 | **Partial** | Declared minimum; no real local WP integration run on PHP 8.4. |
| Current stable PHP | **Unverified** | Local runtime was a development build, not a stable-release matrix. |
| Composer dependencies | **Fail** | No lockfile and shipped packages violate declared constraints. |
| Entra ID / OIDC | **Fail by default configuration** | The default discovery endpoint conflicts with the plugin’s claimed v2 OAuth model. |
| Graph role mapping | **Conditional** | Requires current permission/consent validation and live Graph contract tests. |

# P0 — Release blockers

## 1. Correct the default Entra OpenID Connect discovery endpoint

**Gap:** `Settings::DEFAULT_OPENID_CONFIGURATION_ENDPOINT` is `https://login.microsoftonline.com/organizations/.well-known/openid-configuration`, but authorization is constructed as a v2 scope-based authorization-code flow. The issuer-validation code also expects v2 issuer forms.

**Required resolution**

1. Default to the explicit Entra v2.0 discovery endpoint.
2. Validate discovery-document issuer, authorization endpoint, token endpoint, JWKS URI, response types, and supported signing algorithms before enabling login.
3. Reject discovery data that is incompatible with the configured tenant mode or v2 requirements.
4. Add tests for tenant-specific, `organizations`, `common`, and supported sovereign-cloud discovery endpoints.
5. Migrate existing defaults safely and give administrators a visible action item.

**Acceptance criteria:** Fresh setup succeeds against a current Entra v2 tenant; invalid/mismatched metadata fails closed; documented test evidence covers all advertised tenant modes.

## 2. Commit a Composer lockfile and make release dependencies reproducible

**Gap:** Production `vendor/` is committed, but `composer.lock` is absent. The activation workflow copies that vendor tree into the plugin artifact.

**Required resolution**

1. Generate and commit `composer.lock` from a clean supported-PHP build.
2. Build production `vendor/` only with `composer install --no-dev --prefer-dist --optimize-autoloader` from that lockfile.
3. Add CI validation that fails when installed packages differ from the lockfile.
4. Generate an SBOM, license inventory, package provenance, and checksums for every release.
5. Remove all development tooling from the released plugin artifact.

**Acceptance criteria:** The release artifact is reproducible, contains only locked production dependencies, and its installed package metadata exactly matches the lockfile.

## 3. Resolve all manifest-to-vendor version violations

**Gap:** The bundled vendor tree is older than several direct constraints, including `firebase/php-jwt`, `guzzlehttp/psr7`, `symfony/options-resolver`, `symfony/cache`, and `symfony/http-client`.

**Required resolution**

1. Reinstall from the new lockfile in a clean workspace.
2. Verify every direct and transitive package supports each declared PHP version.
3. Run `composer validate --strict`, `composer check-platform-reqs`, and a locked vulnerability audit in CI.
4. Track deprecations, abandoned packages, licensing, and advisories.

**Acceptance criteria:** Every shipped package satisfies `composer.json`, the locked audit passes, and security updates are traceable.

## 4. Pin and pass a real WordPress 7.1.2 test matrix

**Gap:** Plugin headers and `readme.txt` say “Tested up to: 6.9.4”.

**Required resolution**

1. Run required CI against exact WordPress 7.1.2.
2. Test the minimum supported PHP and the current supported stable PHP release.
3. Test single site, multisite if claimed, default and persistent object cache, Apache/Nginx, and HTTPS/reverse-proxy deployment.
4. Update both metadata files to 7.1.2 only after the matrix passes.

**Acceptance criteria:** A pinned 7.1.2 matrix is green and protected by branch rules; release metadata truthfully reflects it.

## 5. Repair the WordPress Plugin Check CI job

**Gap:** The job labelled “WordPress Plugin Check (Latest WP)” sets `wp-version: '8.4.1'` and allows failure with `continue-on-error: true`.

**Required resolution**

1. Set the intended WordPress version to 7.1.2.
2. Remove `continue-on-error`.
3. Pin the action version under the organization’s action-supply-chain policy.
4. Archive results and fail the release for untriaged warnings/errors.

**Acceptance criteria:** Plugin Check is a required passing status against WP 7.1.2.

## 6. Establish and test a PHP support policy

**Gap:** PHP 8.4 is declared as minimum and 8.5 as tested, yet CI runs only PHP 8.4.1 and local testing used a `-dev` build.

**Required resolution**

1. Publish minimum, current-stable, and end-of-support PHP policy.
2. Test each supported PHP release/SAPI in the WP 7.1.2 integration matrix.
3. Add extension/platform checks and fail CI on PHP warnings/deprecations.
4. Synchronize PHP version statements in code, Composer, CI, and documentation.

**Acceptance criteria:** All advertised PHP versions have passing functional and integration evidence without new warnings/deprecations.

## 7. Make tenant restriction secure by default

**Gap:** `tenantRestrictionMode` defaults to `none`, causing `tid` policy validation to be bypassed.

**Required resolution**

1. Default new deployments to single-tenant mode with a required tenant GUID.
2. Require explicit, reviewed allowlists for multi-tenant operation.
3. Treat `/organizations` and `/common` without tenant constraints as dangerous configurations.
4. Block auto-provisioning unless a valid tenant restriction is enforced.
5. Add Site Health warnings for unsafe tenant configuration.

**Acceptance criteria:** A token from an unapproved tenant is always rejected; new configurations cannot enable SSO without an approved tenant policy.

## 8. Replace automatic mutable-claim account linking with reviewed immutable migration

**Gap:** Although immutable `oid`/`tid` linking exists, mutable email/UPN/login heuristics remain available by default and a heuristic match writes the incoming immutable identity to the local account.

**Required resolution**

1. Enable forced immutable linking by default for new deployments.
2. Provide an administrator-reviewed migration workflow with evidence, approver, date, and audit record.
3. Never automatically link privileged WordPress accounts.
4. Detect duplicate Entra object/tenant mappings.
5. Retire mutable fallback after a documented migration window.

**Acceptance criteria:** No new automatic identity binding occurs through email, UPN, or login name; all legacy bindings are auditable and reviewed.

## 9. Define a deterministic role-mapping privilege policy

**Gap:** Every matching Entra group mapping is added as a WordPress role, creating cumulative effective capabilities.

**Required resolution**

1. Select one policy: deny conflicting matches, explicit priority, least privilege, or approved multi-role combinations.
2. Forbid `administrator` mapping by default and require a separate dangerous-action confirmation.
3. Validate role existence and group GUIDs at save time.
4. Test role addition/removal, conflicts, Graph errors, and loss of group membership.
5. Log role transitions without tokens or raw PII.

**Acceptance criteria:** Each group set has a deterministic, tested authorization result and cannot silently elevate privilege.

## 10. Replace or rigorously harden native PHP sessions

**Gap:** The plugin starts a native PHP session during `login_init` and uses it for OAuth state, nonce, PKCE, redirects, and Graph token material.

**Required resolution**

1. Prefer a WordPress-native short-lived server-side state store where feasible.
2. If sessions remain, document shared session-storage, reverse-proxy TLS, headers-sent, cache, and plugin-conflict requirements.
3. Enforce session expiry, cleanup after all callbacks, Secure/HttpOnly/SameSite attributes, and safe behavior when sessions cannot start.
4. Add concurrent-tab, replay, multi-node, and already-started-session tests.

**Acceptance criteria:** The flow is reliable on common managed WordPress and multi-node deployments and fails safely under session errors.

## 11. Do not persist Graph access tokens in the session

**Gap:** Token responses write `access_token` and unvalidated `token_type` into `$_SESSION`.

**Required resolution**

1. Retain Graph tokens only in process memory until group evaluation completes.
2. If persistence is essential, encrypt, expire, and explicitly destroy token storage.
3. Require token type `Bearer`.
4. Remove `offline_access` unless a secure refresh-token lifecycle is implemented.

**Acceptance criteria:** Successful login leaves no Graph/refresh token in session storage.

## 12. Remove or strictly gate secret-bearing debug output

**Gap:** `print_debug()` outputs complete session, GET, stored settings, and resolved settings values.

**Required resolution**

1. Remove it from production or restrict it to non-production, `WP_DEBUG`, `manage_options`, nonce-protected access, and mandatory redaction.
2. Never display client secrets, tokens, authorization codes, state, nonce, or PKCE verifiers.
3. Add automated tests that scan diagnostics/logs for secrets.

**Acceptance criteria:** No support/debug path can disclose sensitive OAuth or application-secret material.

# P1 — High-priority security and resilience work

## 13. Add live Entra and Graph end-to-end contract tests

- Use a dedicated test tenant/app registration and CI secrets vault.
- Cover authorization code, PKCE, state/nonce replay, issuer/audience/`azp`/`tid`, key rotation, expiry, consent failure, MFA/Conditional Access, Graph failures, and group-role mapping.
- Test advertised tenant/account modes: single tenant, approved multi-tenant, guest/B2B, and MSA behavior.

## 14. Add JWKS cache, key rotation, and outage controls

- Cache by HTTP cache directives with bounded TTL.
- Refresh once on an unknown key ID.
- Handle malformed responses, timeout, 429, and 5xx safely.
- Instrument refresh outcome and cache age.

## 15. Enforce HTTPS and trusted Microsoft endpoint origins

- Require HTTPS for discovery, token/JWKS/authorization/Graph, redirect, and logout endpoints in production.
- Default allowlist official Microsoft cloud domains; make custom/sov-cloud support explicit profiles.
- Verify discovery-derived endpoint origin consistency and prevent configuration-based SSRF.

## 16. Restrict authorization decisions to Graph v1.0

- Disallow `beta` for production group/role authorization.
- Permit beta only under explicit non-production guardrails.
- Validate current `checkMemberGroups` behavior and permissions against the test tenant.

## 17. Complete Graph permission, consent, and capability governance

- Reconfirm current delegated permission and admin-consent requirements.
- Add setup preflight that detects missing consent/capability before user login.
- Document least-privilege alternatives such as claims/app roles where appropriate.
- Translate consent errors safely without raw Graph internals.

## 18. Add strict configuration preflight and health diagnostics

- Validate client ID, tenant IDs, group IDs, redirect URIs, logout URI, endpoint HTTPS/origin, and role mappings.
- Confirm app-registration requirements without storing or printing secrets.
- Add a “test configuration” action and WordPress Site Health checks.

## 19. Define a strict Entra token-claim policy

- Document mandatory claims and allowed types for every supported account category.
- Require `tid` for enterprise flows.
- Define clock-skew, guest, MSA, federated, service-principal, missing-email, and missing-UPN policy.
- Add negative test vectors for every validation branch.

## 20. Add state expiry and replay defenses

- Store issuance time and a short expiry with state/nonce/PKCE.
- Use constant-time state comparison.
- Destroy pending values after both success and failure.
- Support multiple concurrent logins through bounded indexed state entries.

## 21. Strengthen outbound HTTP reliability and observability

- Define connect/read/total timeouts, safe retries, 429 handling, correlation IDs, User-Agent, and circuit breakers.
- Decide whether to use WordPress HTTP API for platform proxy/CA compatibility.
- Add sanitized metrics and health checks.

## 22. Default to local post-login/logout redirects

- Set external redirect blocking by default.
- Test encoded, Unicode/IDN, backslash, CRLF, port, IPv6, and double-encoding bypass cases.
- Require `wp_safe_redirect()` as final redirect protection with immediate termination.

## 23. Add comprehensive audit logging

- Audit configuration changes, identity links, login outcomes, tenant decisions, user provisioning, and role changes.
- Include correlation ID, actor, target, time, old/new roles, and policy decision.
- Exclude all secret/token/raw-claim content.
- Support enterprise log forwarding hooks and retention policy.

## 24. Harden log/cache filesystem storage

- Avoid relying on `.htaccess`, which does not protect all web servers.
- Prefer storage outside web roots, restrictive permissions, and secure ownership.
- Test read-only/container/shared-host/multisite behavior.
- Do not use the plugin directory as a writable fallback in production.

## 25. Make test runs clean

- Eliminate PHPUnit deprecations/notices and resolve skipped-test coverage.
- Fail CI on newly introduced notices/deprecations.
- Add security-critical coverage thresholds.

## 26. Test activation, upgrade, rollback, deactivation, and uninstall

- Test complete lifecycle on WP 7.1.2.
- Version migrations, make them idempotent, and define retention/deletion policy for identity metadata.
- Test network activation and multisite behavior if claimed.

## 27. Define multisite support explicitly

- Decide scope of settings, user linking, roles, sessions, redirects, and logs.
- Test network activation, super admins, site activation, mapped domains, and per-site roles.
- Reject unsupported multisite paths visibly.

## 28. Repair localization, accessibility, and admin UX

- Use one canonical text domain consistently in header, code, POT, tests, and package slug.
- Regenerate translations and test localized/RTL settings screens.
- Run WordPress accessibility and coding-standard checks.

# P2 — Robustness and operational maturity

## 29. Implement or remove refresh-token scope

- Remove `offline_access` unless refresh tokens are necessary.
- If retained, implement encrypted storage, rotation, expiry, revocation, incident response, and least privilege.

## 30. Support Entra interaction-required scenarios safely

- Test and provide safe UX for MFA, Conditional Access, consent, password change, disabled accounts, and interaction-required errors.

## 31. Define account-type support boundaries

- Explicitly support or reject B2B guests, cross-tenant sync, consumer MSA, federation, and external ID/B2C.
- Provide claim/linking policy and test coverage for each supported mode.

## 32. Add rate limiting and outage protection

- Rate-limit callback/login failures and upstream calls.
- Integrate with WordPress/WAF protection.
- Add bounded circuit breakers and clear incident behavior for Entra/Graph outages.

## 33. Add enterprise secret management

- Support environment variables or WordPress constants for secrets.
- Provide secret rotation/expiry guidance and alerts.
- Ensure exports, migrations, support bundles, and logs never disclose secrets.

## 34. Govern configuration export/import and migration

- Exclude secrets by default.
- Integrity-protect imported settings.
- Require capability/nonce checks and audit reset/import/migration actions.
- Test malformed and malicious legacy input.

## 35. Test concurrency and race conditions

- Test parallel first logins, provisioning, identity migration, role changes, and concurrent tabs.
- Add uniqueness/transactional safeguards where required.

## 36. Validate all role/group mappings on save

- Require valid GUID group IDs and existing role slugs.
- Deduplicate values and reject empty/ambiguous mappings.
- Preview risky mapping changes before activation.

## 37. Make issuer validation cloud-aware and metadata-derived

- Derive expected issuer patterns from trusted discovery data.
- Explicitly support approved Microsoft sovereign clouds.
- Avoid a single hard-coded public-cloud issuer pattern.

## 38. Maintain a formal threat model

- Cover token substitution, account takeover, replay, session fixation, SSRF, privilege escalation, logout CSRF, and settings tampering.
- Map controls to OAuth/OIDC best current practice, Entra claim validation guidance, WordPress security guidance, and OWASP ASVS.

## 39. Add fuzzing and hostile-input tests

- Fuzz tokens, claims, JWKS, metadata, Graph responses, redirects, imports, Unicode, oversized inputs, duplicate JSON keys, and unexpected data types.

## 40. Establish performance and scale budgets

- Load-test callback throughput, cache behavior, Graph group mapping, large mappings, and Entra/Graph outage response.
- Measure request volume, worker use, latency, and cache hit rate.

## 41. Publish upgrade/rollback policy

- Provide idempotent versioned migrations, historical upgrade tests, and rollback safety without destructive data loss.

## 42. Publish incident response and support policy

- Define support windows, vulnerability disclosure, security SLA, Entra/Graph outage runbooks, secret compromise, role-elevation, and identity-linking incident procedures.

# P3 — Release engineering and external assurance

## 43. Build a clean, attestable release artifact

- Build plugin zip in CI from locked production dependencies.
- Exclude tests/tooling/caches and scan the artifact.
- Produce checksums, SBOM, provenance, and install/activate the exact zip on WP 7.1.2.

## 44. Align documentation with behavior

- Keep code comments, headers, README, `readme.txt`, settings UI, PHP support, Entra registration, Graph permission, tenant, session, proxy, and operational documentation in sync.

## 45. Make WordPress quality/security checks release gates

- Require WPCS, Plugin Check, escaping/sanitization/nonce/capability/filesystem/i18n checks.
- Do not permit non-blocking security checks or unexplained suppressions.

## 46. Automate dependency maintenance

- Configure reviewed automated Composer updates.
- Require lockfile diff, security audit, license scan, and WP/PHP matrix for each update.
- Maintain emergency patch/release process.

## 47. Add enterprise health checks and telemetry

- Implement sanitized Site Health checks for autoloader, dependencies, extensions, endpoint reachability, metadata freshness, tenant policy, Graph consent, secret expiry, and secure storage.
- Record non-PII outcome metrics and alert thresholds.

## 48. Obtain independent security assessment

- Conduct external OIDC/Entra/Graph/WordPress penetration testing and code review.
- Remediate and retest all high/critical findings before certification.

# Recommended implementation order

1. Complete P0 items 1–6: identity-default correctness, reproducible dependencies, and exact WP/PHP validation.
2. Complete P0 items 7–12: secure tenancy, immutable identity links, authorization policy, session/token handling, and diagnostics.
3. Complete P1: live Entra/Graph contract testing and runtime resilience.
4. Complete P2: scale, governance, migration, and operational maturity.
5. Complete P3: release provenance, continuous assurance, and independent review.

# Certification definition of done

The addon may be called enterprise-grade and compatible with the stated targets only when:

1. Required integration tests pass on exact WordPress 7.1.2 and all published PHP versions.
2. A committed Composer lockfile, exact production `vendor/`, locked vulnerability audit, license scan, and SBOM are present.
3. A dedicated Entra test tenant proves current discovery, authorization-code + PKCE, token validation, tenant restrictions, key rotation, consent, Graph group authorization, and error handling.
4. Secure defaults require tenant restriction and immutable user identity linking.
5. Privileged role mapping is deterministic, minimized, audited, and fully tested.
6. No secret, token, or raw claim is exposed by logs, debug output, caches, exports, or errors.
7. Plugin Check, security checks, and the test matrix are mandatory passing release gates.
8. Independent security assessment has no unresolved high or critical finding.
