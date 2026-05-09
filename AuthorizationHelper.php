<?php

declare(strict_types=1);

use Firebase\JWT\{BeforeValidException, ExpiredException, JWK, JWT, SignatureInvalidException};
use Psr\Http\Message\ResponseInterface;

/**
 * PKCE (Proof Key for Code Exchange) implementation per RFC 7636.
 *
 * References:
 * - https://datatracker.ietf.org/doc/html/rfc7636
 * - https://www.rfc-editor.org/rfc/rfc7636
 * - https://oauth.com/oauth2-servers/pkce/
 *
 * PKCE is mandatory for all OAuth 2.0 clients per OAuth 2.1 and provides
 * protection against authorization code interception attacks.
 */

/**
 * Generate a standards-compliant PKCE code_verifier.
 *
 * Per RFC 7636:
 * - MUST be between 43 and 128 characters (inclusive)
 * - MUST use only unreserved characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 * - RECOMMEND 256 bits of entropy (32 bytes → 43 chars when base64url-encoded)
 *
 * @return string The generated code_verifier
 */
function aad_sso_generate_pkce_code_verifier(): string
{
    // Generate 32 bytes of cryptographically secure random data
    // This produces 43 characters when base64url-encoded without padding
    $random_bytes = random_bytes(32);

    // Base64url encode (RFC 4648 Section 5 with URL-safe alphabet)
    return mb_rtrim(strtr(base64_encode($random_bytes), '+/', '-_'), '=');
}

/**
 * Generate a PKCE code_challenge using S256 method.
 *
 * Per RFC 7636:
 * - code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
 * - S256 method is REQUIRED (plaintext method is deprecated)
 *
 * @param string $code_verifier The code_verifier string
 *
 * @return string The S256 code_challenge
 */
function aad_sso_generate_pkce_code_challenge(string $code_verifier): string
{
    // Compute SHA-256 hash of the verifier string (using binary output)
    $hash = hash('sha256', $code_verifier, true);

    // Base64url encode the hash without padding
    return mb_rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
}

/**
 * Validate a PKCE code_verifier against an expected code_challenge.
 *
 * @param string $code_verifier      The verifier to validate
 * @param string $expected_challenge The expected code_challenge from the authorization request
 *
 * @return bool True if the verifier produces the expected challenge
 */
function aad_sso_validate_pkce_code_verifier(string $code_verifier, string $expected_challenge): bool
{
    // Validate code_verifier format per RFC 7636
    // Must be 43-128 characters, using only unreserved characters
    if (!preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $code_verifier)) {
        return false;
    }

    // Compute the challenge from the verifier and compare
    $computed_challenge = aad_sso_generate_pkce_code_challenge($code_verifier);

    // Use constant-time comparison to prevent timing attacks
    return hash_equals($expected_challenge, $computed_challenge);
}

class AuthorizationHelper
{
    /**
     * Base scopes required for OpenID Connect authentication.
     */
    private const BASE_SCOPES = ['openid', 'email', 'profile'];

    /**
     * Scopes required for Microsoft Graph API access.
     */
    private const GRAPH_SCOPES = [
        'User.Read',
        'GroupMember.Read.All',
    ];

    /**
     * @var null|AADSSO_HttpClient
     */
    private static ?AADSSO_HttpClient $http_client = null;

    /**
     * @var array<int, string>
     */
    private static array $allowed_algorithms = ['RS256'];

    /**
     * Builds the OAuth scope string for the authorization request.
     * Uses V2.0 pattern with scope parameter instead of V1.0 resource parameter.
     *
     * @param AADSSO_Settings $settings
     *
     * @return string Space-separated list of scopes
     */
    public static function build_scope_string(AADSSO_Settings $settings): string
    {
        $scopes = self::BASE_SCOPES;

        // Add offline_access for refresh token support
        $scopes[] = 'offline_access';

        // Add Graph API scopes if group-based role mapping is enabled
        if ($settings->enable_aad_group_to_wp_role) {
            foreach (self::GRAPH_SCOPES as $graph_scope) {
                $full_scope = 'https://graph.microsoft.com/' . $graph_scope;
                if (!\in_array($full_scope, $scopes, true)) {
                    $scopes[] = $full_scope;
                }
            }
        }

        // Add any custom scopes configured by the administrator
        $custom_scope = $settings->custom_scope ?? '';
        if (!empty($custom_scope) && \is_string($custom_scope)) {
            $custom_scopes = array_filter(
                array_map('trim', explode(' ', $custom_scope))
            );
            foreach ($custom_scopes as $custom_scope_item) {
                if (!empty($custom_scope_item) && !\in_array($custom_scope_item, $scopes, true)) {
                    $scopes[] = $custom_scope_item;
                }
            }
        }

        return implode(' ', $scopes);
    }

    /**
     * Build the authorization URL with PKCE.
     *
     * Per RFC 7636 (PKCE) and Microsoft identity platform:
     * - Include code_challenge and code_challenge_method in authorization request
     * - S256 is the only supported method (plain is deprecated)
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7636
     * @see https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
     *
     * @param AADSSO_Settings $settings
     * @param string          $antiforgery_id
     * @param string          $code_verifier  The PKCE code_verifier (stored in session for token exchange)
     *
     * @return string The authorization URL
     */
    public static function get_authorization_url(AADSSO_Settings $settings, string $antiforgery_id, string $code_verifier): string
    {
        $scope_string = self::build_scope_string($settings);

        // Generate the S256 code_challenge from the verifier
        $code_challenge = aad_sso_generate_pkce_code_challenge($code_verifier);

        // Use V2.0 endpoint query parameters for scope-based authorization
        return $settings->authorization_endpoint . '?'
            . http_build_query([
                'response_type' => 'code',
                'scope' => $scope_string,
                'domain_hint' => $settings->org_domain_hint,
                'client_id' => $settings->client_id,
                'redirect_uri' => $settings->redirect_uri,
                'state' => $antiforgery_id,
                'nonce' => $antiforgery_id,
                // PKCE parameters (RFC 7636)
                'code_challenge' => $code_challenge,
                'code_challenge_method' => 'S256',
            ]);
    }

    /**
     * Get access token from authorization code with PKCE verification.
     *
     * Per RFC 7636 (PKCE):
     * - The code_verifier must be sent during token exchange
     * - The authorization server verifies that the code_verifier matches the code_challenge
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7636
     *
     * @param string          $code          The authorization code
     * @param AADSSO_Settings $settings
     * @param string          $code_verifier The PKCE code_verifier (previously generated and stored)
     *
     * @return mixed
     */
    public static function get_access_token(string $code, AADSSO_Settings $settings, string $code_verifier): mixed
    {
        $scope_string = self::build_scope_string($settings);

        // Validate the code_verifier format before using it
        if (!preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $code_verifier)) {
            AADSSO_Logger::log_error('Invalid PKCE code_verifier format received');

            return new WP_Error(
                'invalid_pkce_verifier',
                'Invalid PKCE code_verifier format. The verifier must be 43-128 characters using unreserved characters.'
            );
        }

        // Use V2.0 token request with scope parameter instead of resource parameter
        // Include code_verifier for PKCE (RFC 7636)
        $authentication_request_body = http_build_query([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $settings->redirect_uri,
            'scope' => $scope_string,
            'client_id' => $settings->client_id,
            'client_secret' => $settings->client_secret,
            'code_verifier' => $code_verifier,
        ]);

        return self::get_and_process_access_token($authentication_request_body, $settings);
    }

    public static function get_and_process_access_token(
        string $authentication_request_body,
        AADSSO_Settings $settings
    ): mixed {
        $options = [
            'body' => $authentication_request_body,
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
        ];

        try {
            $response = self::get_http_client()->post($settings->token_endpoint, $options);

            return self::process_token_response($response);
        } catch (Throwable $e) {
            AADSSO_Logger::log_error(
                'Token request error: ' . $e->getMessage()
            );

            return new WP_Error(
                'http_request_failed',
                'Token request failed: ' . $e->getMessage()
            );
        }
    }

    public static function validate_id_token(
        string $id_token,
        AADSSO_Settings $settings,
        string $antiforgery_id
    ): object {
        $response = null;

        try {
            $response = self::get_http_client()->get($settings->jwks_uri);
        } catch (Throwable $e) {
            throw new DomainException('Failed to fetch JWKS: ' . $e->getMessage());
        }

        return self::process_jwks_response($response, $id_token, $antiforgery_id, $settings->client_id);
    }

    /**
     * Validate the tenant ID (tid) claim against configured tenant restrictions.
     *
     * Per Microsoft identity platform guidance:
     * "Always check that the tid in a token matches the tenant ID used to store data
     * with the application. When information is stored in the context of a tenant,
     * it should only be accessed again later in the same tenant. Never allow data
     * in one tenant to be accessed from another tenant."
     *
     * @see https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation
     * @see https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
     *
     * @param object $jwt      The decoded JWT token object
     * @param object $settings The plugin settings containing tenant restriction config
     */
    public static function validate_tenant_id(object $jwt, object $settings): void
    {
        // Get tenant restriction mode: 'none', 'single', or 'multi'
        $mode = $settings->tenantRestrictionMode ?? 'none';

        // If tenant restriction is disabled, accept any valid tenant
        if ('none' === $mode) {
            return;
        }

        // Extract tid claim from token
        // The tid claim is present in all work/school account tokens
        // For personal Microsoft accounts (MSA) in the tenant, value is 9188040d-6c67-4c5b-b112-36a304b66dad
        $token_tid = null;
        if (isset($jwt->tid) && \is_string($jwt->tid)) {
            $token_tid = $jwt->tid;
        }

        if (null === $token_tid || '' === $token_tid) {
            // tid claim is missing - this could indicate a malformed token
            // or a token from an unexpected identity provider
            throw new DomainException('ID token is missing required `tid` (tenant ID) claim. This token may not be from a valid Microsoft Entra ID tenant. For personal Microsoft accounts, ensure the endpoint supports MSA if intended.');
        }

        switch ($mode) {
            case 'single':
                // Single-tenant mode: require exact match with expected_tenant_id
                $expected = $settings->expected_tenant_id ?? '';
                if ('' === $expected) {
                    // If tenant restriction mode is 'single' but no tenant is configured,
                    // this is a configuration error - reject all tokens
                    AADSSO_Logger::log_error(
                        'Tenant restriction mode is set to "single" but no expected tenant ID is configured. '
                        . 'Please configure the expected tenant ID in the plugin settings.'
                    );
                    throw new DomainException('Tenant restriction is enabled but no expected tenant ID is configured. Please configure the expected tenant ID in the plugin settings.');
                }

                if (!self::is_valid_guid($expected)) {
                    AADSSO_Logger::log_error(
                        'Configured expected tenant ID is not a valid GUID: ' . $expected
                    );
                    throw new DomainException('Configured expected tenant ID is not a valid GUID format.');
                }

                // Case-insensitive comparison for GUIDs
                if (!strcasecmp($token_tid, $expected)) {
                    AADSSO_Logger::log_info(
                        'Tenant ID validated: token tid matches expected tenant',
                        ['tid' => $token_tid]
                    );

                    return;
                }

                AADSSO_Logger::log_error(\sprintf(
                    'Tenant ID mismatch. Expected "%s", got "%s"',
                    $expected,
                    $token_tid
                ));
                throw new DomainException(\sprintf('ID token tenant ID validation failed. Token is from tenant "%s", but only "%s" is allowed.', $token_tid, $expected));

            case 'multi':
                // Multi-tenant controlled mode: require tid to be in allowed_tenant_ids
                $allowed = $settings->allowed_tenant_ids ?? [];
                if (empty($allowed)) {
                    // If tenant restriction mode is 'multi' but no allowed tenants are configured,
                    // this is a configuration error - reject all tokens
                    AADSSO_Logger::log_error(
                        'Tenant restriction mode is set to "multi" but no allowed tenant IDs are configured. '
                        . 'Please configure at least one allowed tenant ID in the plugin settings.'
                    );
                    throw new DomainException('Tenant restriction is enabled but no allowed tenant IDs are configured. Please configure allowed tenant IDs in the plugin settings.');
                }

                // Case-insensitive comparison for GUIDs
                $found = false;
                foreach ($allowed as $allowed_tid) {
                    if (!strcasecmp($token_tid, $allowed_tid)) {
                        $found = true;

                        break;
                    }
                }

                if ($found) {
                    AADSSO_Logger::log_info(
                        'Tenant ID validated: token tid is in allowed tenants list',
                        ['tid' => $token_tid]
                    );

                    return;
                }

                AADSSO_Logger::log_error(\sprintf(
                    'Tenant ID "%s" is not in the allowed tenants list.',
                    $token_tid
                ));
                throw new DomainException(\sprintf('ID token tenant ID validation failed. Token is from tenant "%s", which is not in the allowed tenants list.', $token_tid));

            default:
                // Unknown mode - this should not happen with proper sanitization
                AADSSO_Logger::log_warning(
                    'Unknown tenant restriction mode: ' . $mode . '. Treating as disabled.'
                );

                return;
        }
    }

    private static function get_http_client(): AADSSO_HttpClient
    {
        if (!isset(self::$http_client)) {
            self::$http_client = AADSSO_HttpClient::get_instance();
        }

        return self::$http_client;
    }

    private static function process_token_response(ResponseInterface $response): mixed
    {
        $status_code = $response->getStatusCode();
        $response_body = $response->getBody()->getContents();

        if ($status_code >= 400) {
            AADSSO_Logger::log_error('Token request failed with HTTP ' . $status_code . ': ' . $response_body);

            return new WP_Error(
                'token_request_failed',
                'Token request failed with HTTP ' . $status_code
            );
        }

        $result = json_decode($response_body, true);

        if (!\is_array($result)) {
            AADSSO_Logger::log_error('Token response JSON decode error: ' . json_last_error_msg());

            return new WP_Error('invalid_json_response', 'Token response could not be decoded');
        }

        if (isset($result['access_token']) && \PHP_SESSION_ACTIVE === session_status()) {
            $token_type = $result['token_type'] ?? 'Bearer';
            $access_token_raw = $result['access_token'];
            $access_token = \is_string($access_token_raw) ? $access_token_raw : '';
            $_SESSION['aadsso_token_type'] = $token_type;
            $_SESSION['aadsso_access_token'] = $access_token;

            // Store refresh token if provided
            $refresh_token_raw = $result['refresh_token'] ?? '';
            if (\is_string($refresh_token_raw) && '' !== $refresh_token_raw) {
                $_SESSION['aadsso_refresh_token'] = $refresh_token_raw;
            }

            // Store token expiration timestamp
            // expires_in is in seconds from the token response
            $expires_in_raw = $result['expires_in'] ?? 0;
            if (\is_int($expires_in_raw) && $expires_in_raw > 0) {
                $_SESSION['aadsso_token_expires_at'] = time() + $expires_in_raw;
            } elseif (\is_numeric($expires_in_raw) && (int) $expires_in_raw > 0) {
                $_SESSION['aadsso_token_expires_at'] = time() + (int) $expires_in_raw;
            }
        }

        return (object) $result;
    }

    private static function process_jwks_response(
        ResponseInterface $response,
        string $id_token,
        string $antiforgery_id,
        string $client_id
    ): object {
        $status_code = $response->getStatusCode();

        if ($status_code >= 400) {
            throw new DomainException('Failed to fetch JWKS: HTTP ' . $status_code);
        }

        $jwks_body = $response->getBody()->getContents();
        $jwks = json_decode($jwks_body, true);

        if (!\is_array($jwks)) {
            throw new DomainException('JWKS response JSON decode error: ' . json_last_error_msg());
        }

        if (empty($jwks['keys']) || !\is_array($jwks['keys'])) {
            throw new DomainException('jwks_uri does not contain valid keys');
        }

        $jwks_keys = $jwks;
        try {
            $keys = JWK::parseKeySet($jwks_keys, 'RS256');
        } catch (Throwable $e) {
            throw new DomainException('Failed to parse JWKS: ' . $e->getMessage());
        }

        // Create allowed algorithms object for JWT::decode
        $allowedAlgorithms = (object) ['RS256' => self::$allowed_algorithms];

        try {
            $jwt = JWT::decode($id_token, $keys, $allowedAlgorithms);
        } catch (ExpiredException $e) {
            throw new DomainException('Token has expired');
        } catch (SignatureInvalidException $e) {
            throw new DomainException('Token signature verification failed');
        } catch (BeforeValidException $e) {
            throw new DomainException('Token is not yet valid');
        } catch (Throwable $e) {
            throw new DomainException('Token validation failed: ' . $e->getMessage());
        }

        // Defensive check - though JWT::decode() is declared to return object
        // @phpstan-ignore-next-line
        if (!\is_object($jwt)) {
            throw new DomainException('JWT decode returned non-object');
        }

        // ─────────────────────────────────────────────────────────────────────
        // ID Token audience (aud) validation
        //
        // Per Microsoft identity platform guidance (as of May 2026):
        // - v2.0 tokens: `aud` must equal the client application ID (GUID)
        // - v1.0 tokens: `aud` must equal the App ID URI (api://{clientId})
        //
        // This plugin uses v2.0 endpoints exclusively. The `aud` claim may be
        // a string or array of strings. When present, `azp` (authorized party)
        // should match the client_id for confidential-client scenarios.
        //
        // References:
        // - https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation
        // - https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
        // - https://openid.net/specs/openid-connect-core-1_0-final.html (Section 3.1.3.7)
        //
        // Note: v1.0 endpoints are deprecated; v2.0 is the only supported path.
        // ─────────────────────────────────────────────────────────────────────

        $aud_claim = $jwt->aud ?? null;
        if (null === $aud_claim) {
            throw new DomainException('ID token is missing required `aud` (audience) claim');
        }

        // Handle aud as string or array
        $aud_values = [];
        if (\is_string($aud_claim)) {
            $aud_values = [$aud_claim];
        } elseif (\is_array($aud_claim)) {
            $aud_values = array_filter($aud_claim, 'is_string');
        }

        if (empty($aud_values)) {
            throw new DomainException('ID token `aud` claim has invalid format');
        }

        // Validate that the configured client_id is in the audience list
        if (!\in_array($client_id, $aud_values, true)) {
            throw new DomainException(\sprintf('ID token audience validation failed. Expected `%s`, got `%s`', $client_id, implode(', ', $aud_values)));
        }

        // ─────────────────────────────────────────────────────────────────────
        // Authorized Party (azp) validation
        //
        // Per OIDC Core 1.0 Section 3.1.3.7 and Microsoft guidance (May 2026):
        // - `azp` is present when the token has a single audience and the
        //   authorized party differs from the audience
        // - For confidential clients (which this WordPress plugin represents),
        //   the `azp` MUST match the client_id if present
        // - For multi-audience tokens (array aud with multiple values),
        //   azp SHOULD be present and MUST contain the client_id
        //
        // Microsoft Entra ID specification (May 2026):
        // - `azp` is defined as "String, a GUID" (per access token claims reference)
        // - If present but not a string, the token is MALFORMED and MUST be rejected
        //
        // Note: v1.0 endpoints are deprecated; v2.0 is the only supported path.
        //
        // References:
        // - https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
        // - https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation
        // - https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference
        // - https://openid.net/specs/openid-connect-core-1_0-final.html (Section 3.1.3.7)
        // ─────────────────────────────────────────────────────────────────────

        $azp_claim = $jwt->azp ?? null;

        // Validate azp presence for multi-audience tokens (OIDC Core 1.0 Section 3.1.3.7)
        // Per spec: "If the ID Token contains multiple audiences, the Client SHOULD verify
        // that an azp Claim is present."
        // Note: $aud_values is always an array (set earlier from aud claim processing)
        if (\count($aud_values) > 1 && null === $azp_claim) {
            // For multi-audience tokens without azp, log a warning but don't block.
            // This is a SHOULD requirement (not MUST), and most Microsoft Entra tokens
            // with multiple audiences will include azp anyway.
            AADSSO_Logger::log_warning(
                'Multi-audience ID token does not contain azp claim. '
                . 'While not required, including azp improves security.',
                ['audiences' => $aud_values]
            );
        }

        // azp claim type validation
        // Microsoft Entra ID specifies azp as "String, a GUID". If azp is present
        // but not a string, the token is malformed and MUST be rejected per the
        // Zero Trust principle: reject unexpected claim formats.
        if (null !== $azp_claim && !\is_string($azp_claim)) {
            throw new DomainException(\sprintf('ID token contains malformed `azp` claim. Expected string (GUID), got `%s`. This may indicate token tampering or an invalid identity provider.', \gettype($azp_claim)));
        }

        // Validate azp matches client_id if present
        // Per OIDC spec: "If an azp Claim is present, the Client SHOULD verify
        // that its client_id is the Claim Value."
        // For confidential clients like this WordPress plugin, this is MUST.
        if (\is_string($azp_claim) && $azp_claim !== $client_id) {
            // azp is present and does not match expected client_id
            // This may indicate the token was issued for a different application
            throw new DomainException(\sprintf('ID token authorized party (azp) mismatch. Expected `%s`, got `%s`. This token may have been issued for a different application.', $client_id, $azp_claim));
        }

        $token_nonce = $jwt->nonce ?? '';
        /** @var mixed $nonce_val */
        $nonce_val = $token_nonce;
        $token_nonce_str = \is_string($nonce_val) ? $nonce_val : '';
        if ($token_nonce_str !== $antiforgery_id) {
            throw new DomainException(\sprintf('Nonce mismatch. Expecting %s', $antiforgery_id));
        }

        // Note: JWT::decode() (called above) already validates exp and nbf claims
        // via ExpiredException and BeforeValidException respectively.

        // Check token was not issued too far in the past (optional: 24-hour max age)
        $now = time();
        $token_iat = isset($jwt->iat) ? (int) $jwt->iat : 0;
        if ($token_iat > 0) {
            $max_token_age = 86400; // 24 hours
            $token_age = $now - $token_iat;
            if ($token_age > $max_token_age) {
                AADSSO_Logger::log_warning(
                    'Token age exceeds recommended maximum',
                    ['token_age_seconds' => $token_age, 'max_age_seconds' => $max_token_age]
                );
            }
        }

        return $jwt;
    }

    /**
     * Validate that a string is a valid GUID format.
     *
     * @param string $value The string to validate
     *
     * @return bool True if the value is a valid GUID (8-4-4-4-12 hex characters)
     */
    private static function is_valid_guid(string $value): bool
    {
        $trimmed = mb_trim($value);
        if ('' === $trimmed) {
            return false;
        }

        // GUID format: 8-4-4-4-12 hex characters
        return 1 === preg_match('#^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$#i', $trimmed);
    }
}

class_alias(AuthorizationHelper::class, 'AADSSO_AuthorizationHelper');
