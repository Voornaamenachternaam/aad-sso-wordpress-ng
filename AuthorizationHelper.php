<?php

declare(strict_types=1);

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Psr\Http\Message\ResponseInterface;

class AADSSO_AuthorizationHelper
{
    /** @var AADSSO_HttpClient|null */
    private static ?AADSSO_HttpClient $http_client = null;

    private static array $allowed_algorithms = ['RS256'];

    public static function get_authorization_url(AADSSO_Settings $settings, string $antiforgery_id): string
    {
        return $settings->authorization_endpoint . '?'
            . http_build_query([
                'response_type' => 'code',
                'scope' => 'openid',
                'domain_hint' => $settings->org_domain_hint,
                'client_id' => $settings->client_id,
                'resource' => $settings->graph_endpoint,
                'redirect_uri' => $settings->redirect_uri,
                'state' => $antiforgery_id,
                'nonce' => $antiforgery_id,
            ]);
    }

    public static function get_access_token(string $code, AADSSO_Settings $settings): mixed
    {
        $authentication_request_body = http_build_query([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $settings->redirect_uri,
            'resource' => $settings->graph_endpoint,
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

    public static function validate_id_token(
        string $id_token,
        AADSSO_Settings $settings,
        string $antiforgery_id
    ): object {
        try {
            $response = self::get_http_client()->get($settings->jwks_uri);

            return self::process_jwks_response($response, $id_token, $antiforgery_id);
        } catch (\Throwable $e) {
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
            $access_token = (string) $result['access_token'];
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
        } catch (\Throwable $e) {
            throw new DomainException('Failed to parse JWKS: ' . $e->getMessage());
        }

        try {
            $jwt = JWT::decode($id_token, $keys, self::$allowed_algorithms);
        } catch (ExpiredException $e) {
            throw new DomainException('Token has expired');
        } catch (SignatureInvalidException $e) {
            throw new DomainException('Token signature verification failed');
        } catch (BeforeValidException $e) {
            throw new DomainException('Token is not yet valid');
        } catch (\Throwable $e) {
            throw new DomainException('Token validation failed: ' . $e->getMessage());
        }

        $token_nonce = $jwt->nonce ?? '';
        $token_nonce_str = (string) $token_nonce;
        if ($token_nonce_str !== $antiforgery_id) {
            throw new DomainException(\sprintf('Nonce mismatch. Expecting %s', $antiforgery_id));
        }

        return $jwt;
    }
}