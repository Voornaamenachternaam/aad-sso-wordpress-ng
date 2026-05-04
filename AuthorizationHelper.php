<?php

/**
 * Authorization helper class for Microsoft Entra ID SSO.
 *
 * Handles authorization URL generation, access token retrieval,
 * and JWT/ID token validation using PSR-18 HTTP client.
 *
 * @package AADSSO
 */
declare(strict_types=1);

/**
 * Authorization helper class.
 */
class AADSSO_AuthorizationHelper
{
    /** @var AADSSO_HttpClient|null HTTP client instance */
    private static ?AADSSO_HttpClient $http_client = null;

    private static array $allowed_algorithms = array('RS256');

    /**
     * Get the HTTP client instance.
     *
     * @return AADSSO_HttpClient The HTTP client.
     */
    private static function get_http_client(): AADSSO_HttpClient
    {
        if (self::$http_client === null) {
            self::$http_client = AADSSO_HttpClient::get_instance();
        }
        return self::$http_client;
    }

    public static function get_authorization_url(AADSSO_Settings $settings, string $antiforgery_id): string
    {
        $auth_url = $settings->authorization_endpoint . '?'
            . http_build_query(array(
                'response_type' => 'code',
                'scope' => 'openid',
                'domain_hint' => sanitize_text_field($settings->org_domain_hint),
                'client_id' => sanitize_text_field($settings->client_id),
                'resource' => esc_url_raw($settings->graph_endpoint),
                'redirect_uri' => esc_url_raw($settings->redirect_uri),
                'state' => sanitize_text_field($antiforgery_id),
                'nonce' => sanitize_text_field($antiforgery_id),
            ));
        return $auth_url;
    }

    public static function get_access_token(string $code, AADSSO_Settings $settings): mixed
    {
        $authentication_request_body = http_build_query(array(
            'grant_type' => 'authorization_code',
            'code' => (string) $code,
            'redirect_uri' => (string) $settings->redirect_uri,
            'resource' => (string) $settings->graph_endpoint,
            'client_id' => (string) $settings->client_id,
            'client_secret' => (string) $settings->client_secret,
        ));

        return self::get_and_process_access_token($authentication_request_body, $settings);
    }

    public static function get_and_process_access_token(
        string $authentication_request_body,
        AADSSO_Settings $settings
    ): mixed {
        $options = array(
            'body' => $authentication_request_body,
            'headers' => array(
                'Content-Type' => 'application/x-www-form-urlencoded',
            ),
        );

        try {
            $response = self::get_http_client()->post($settings->token_endpoint, $options);
            return self::process_token_response($response);
        } catch (\Throwable $e) {
            AADSSO_Logger::log_error(
                'Token request error: ' . $e->getMessage()
            );
            return new WP_Error(
                'http_request_failed',
                'Token request failed: ' . $e->getMessage()
            );
        }
    }

    /**
     * Process the token response.
     *
     * @param \Psr\Http\Message\ResponseInterface $response The PSR-7 response.
     * @return mixed The decoded response or WP_Error on failure.
     */
    private static function process_token_response(\Psr\Http\Message\ResponseInterface $response): mixed
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

        if (json_last_error() !== JSON_ERROR_NONE) {
            AADSSO_Logger::log_error('Token response JSON decode error: ' . json_last_error_msg());
            return new WP_Error('invalid_json_response', 'Token response could not be decoded');
        }

        if (isset($result['access_token']) && session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION['aadsso_token_type'] = (string) ($result['token_type'] ?? 'Bearer');
            $_SESSION['aadsso_access_token'] = (string) $result['access_token'];
        }

        return (object) $result;
    }

    public static function validate_id_token(
        string $id_token,
        AADSSO_Settings $settings,
        string $antiforgery_id
    ): object {
        try {
            $response = self::get_http_client()->get($settings->jwks_uri);
            return self::process_jwks_response($response, $id_token, $antiforgery_id);
        } catch (\Throwable $e) {
            throw new DomainException(
                'Failed to fetch JWKS: ' . $e->getMessage()
            );
        }
    }

    /**
     * Process JWKS response and validate ID token.
     *
     * @param \Psr\Http\Message\ResponseInterface $response The PSR-7 response.
     * @param string $id_token The ID token to validate.
     * @param string $antiforgery_id The expected nonce value.
     * @return object The decoded and validated JWT.
     * @throws DomainException If validation fails.
     */
    private static function process_jwks_response(
        \Psr\Http\Message\ResponseInterface $response,
        string $id_token,
        string $antiforgery_id
    ): object {
        $status_code = $response->getStatusCode();

        if ($status_code >= 400) {
            throw new DomainException('Failed to fetch JWKS: HTTP ' . $status_code);
        }

        $jwks_body = $response->getBody()->getContents();
        $jwks = json_decode($jwks_body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new DomainException('JWKS response JSON decode error: ' . json_last_error_msg());
        }

        if (!is_array($jwks) || empty($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new DomainException('jwks_uri does not contain valid keys');
        }

        try {
            $keys = \Firebase\JWT\JWK::parseKeySet($jwks, 'RS256');
        } catch (\Throwable $e) {
            throw new DomainException('Failed to parse JWKS: ' . $e->getMessage());
        }

        try {
            $jwt = \Firebase\JWT\JWT::decode($id_token, $keys, self::$allowed_algorithms);
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw new DomainException('Token has expired');
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            throw new DomainException('Token signature verification failed');
        } catch (\Firebase\JWT\BeforeValidException $e) {
            throw new DomainException('Token is not yet valid');
        } catch (\Throwable $e) {
            throw new DomainException('Token validation failed: ' . $e->getMessage());
        }

        $token_nonce = isset($jwt->nonce) ? (string) $jwt->nonce : '';
        if ($token_nonce !== $antiforgery_id) {
            throw new DomainException(
                sprintf('Nonce mismatch. Expecting %s', esc_html($antiforgery_id))
            );
        }

        return $jwt;
    }
}