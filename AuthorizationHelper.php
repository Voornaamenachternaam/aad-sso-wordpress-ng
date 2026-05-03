<?php

declare(strict_types=1);

class AADSSO_AuthorizationHelper
{
    private static array $allowed_algorithms = ['RS256'];

    public static function get_authorization_url($settings, string $antiforgery_id): string
    {
        $auth_url = $settings->authorization_endpoint . '?'
            . http_build_query([
                'response_type' => 'code',
                'scope' => 'openid profile email',
                'domain_hint' => $settings->org_domain_hint,
                'client_id' => $settings->client_id,
                'resource' => $settings->graph_endpoint,
                'redirect_uri' => $settings->redirect_uri,
                'state' => $antiforgery_id,
                'nonce' => $antiforgery_id,
            ]);
        return $auth_url;
    }

    public static function get_access_token(string $code, $settings)
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

    public static function get_and_process_access_token(string $authentication_request_body, $settings)
    {
        $response = wp_remote_post($settings->token_endpoint, [
            'body' => $authentication_request_body,
            'timeout' => 30,
            'sslverify' => true,
        ]);

        if (is_wp_error($response)) {
            return new WP_Error($response->get_error_code(), $response->get_error_message());
        }

        $output = wp_remote_retrieve_body($response);
        $result = json_decode($output);

        if (isset($result->access_token)) {
            if (session_status() === PHP_SESSION_ACTIVE) {
                $_SESSION['aadsso_token_type'] = $result->token_type;
                $_SESSION['aadsso_access_token'] = $result->access_token;
            }
        }

        return $result;
    }

    public static function validate_id_token(string $id_token, $settings, string $antiforgery_id): object
    {
        $jwks_response = wp_remote_get($settings->jwks_uri, [
            'timeout' => 15,
            'sslverify' => true,
        ]);

        if (is_wp_error($jwks_response)) {
            throw new DomainException('Failed to fetch JWKS: ' . $jwks_response->get_error_message());
        }

        $jwks_body = wp_remote_retrieve_body($jwks_response);
        $jwks = json_decode($jwks_body, true);

        if (!is_array($jwks) || empty($jwks['keys'])) {
            throw new DomainException('jwks_uri does not contain valid keys');
        }

        try {
            $keys = \Firebase\JWT\JWK::parseKeySet($jwks, 'RS256');
        } catch (Exception $e) {
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
        } catch (Exception $e) {
            throw new DomainException('Token validation failed: ' . $e->getMessage());
        }

        if (!isset($jwt->nonce) || $jwt->nonce !== $antiforgery_id) {
            throw new DomainException(sprintf('Nonce mismatch. Expecting %s', $antiforgery_id));
        }

        if (isset($jwt->iss)) {
            $expected_iss = $settings->authorization_endpoint;
            $parsed_url = parse_url($expected_iss);
            $expected_iss_base = $parsed_url['scheme'] . '://' . $parsed_url['host'];
            if (strpos($jwt->iss, $expected_iss_base) !== 0) {
                throw new DomainException('Token issuer validation failed');
            }
        }

        if (isset($jwt->aud)) {
            $audiences = is_array($jwt->aud) ? $jwt->aud : [$jwt->aud];
            if (!in_array($settings->client_id, $audiences, true)) {
                throw new DomainException('Token audience validation failed');
            }
        }

        return $jwt;
    }
}