<?php

declare(strict_types=1);

use Firebase\JWT\{BeforeValidException, ExpiredException, JWK, JWT, SignatureInvalidException};
use Psr\Http\Message\ResponseInterface;

class AuthorizationHelper
{
    /**
     * @var null|AADSSO_HttpClient
     */
    private static ?AADSSO_HttpClient $http_client = null;

    /**
     * @var array<int, string>
     */
    private static array $allowed_algorithms = ['RS256'];

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

    public static function get_authorization_url(AADSSO_Settings $settings, string $antiforgery_id): string
    {
        $scope_string = self::build_scope_string($settings);

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
            ]);
    }

    public static function get_access_token(string $code, AADSSO_Settings $settings): mixed
    {
        $scope_string = self::build_scope_string($settings);

        // Use V2.0 token request with scope parameter instead of resource parameter
        $authentication_request_body = http_build_query([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $settings->redirect_uri,
            'scope' => $scope_string,
            'client_id' => $settings->client_id,
            'client_secret' => $settings->client_secret,
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
        try {
            $response = self::get_http_client()->get($settings->jwks_uri);

            return self::process_jwks_response($response, $id_token, $antiforgery_id);
        } catch (Throwable $e) {
            throw new DomainException('Failed to fetch JWKS: ' . $e->getMessage());
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
        }

        return (object) $result;
    }

    private static function process_jwks_response(
        ResponseInterface $response,
        string $id_token,
        string $antiforgery_id
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

        $token_nonce = $jwt->nonce ?? '';
        /** @var mixed $nonce_val */
        $nonce_val = $token_nonce;
        $token_nonce_str = \is_string($nonce_val) ? $nonce_val : '';
        if ($token_nonce_str !== $antiforgery_id) {
            throw new DomainException(\sprintf('Nonce mismatch. Expecting %s', $antiforgery_id));
        }

        return $jwt;
    }
}
