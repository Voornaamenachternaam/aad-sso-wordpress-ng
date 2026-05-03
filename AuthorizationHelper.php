<?php

declare(strict_types=1);

class AADSSO_AuthorizationHelper
{
    private static array $allowed_algorithms = array('RS256');

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
        $response = wp_remote_post(
            esc_url_raw($settings->token_endpoint),
            array(
                'body' => $authentication_request_body,
                'timeout' => 30,
                'sslverify' => true,
                'headers' => array(
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ),
            )
        );

        if (is_wp_error($response)) {
            AADSSO_Logger::log_error(
                'Token request error: ' . $response->get_error_message()
            );
            return new WP_Error(
                $response->get_error_code(),
                $response->get_error_message()
            );
        }

        $output = wp_remote_retrieve_body($response);
        $result = json_decode($output);

        if (isset($result->access_token) && session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION['aadsso_token_type'] = (string) ($result->token_type ?? 'Bearer');
            $_SESSION['aadsso_access_token'] = (string) $result->access_token;
        }

        return $result;
    }

    public static function validate_id_token(
        string $id_token,
        AADSSO_Settings $settings,
        string $antiforgery_id
    ): object {
        $jwks_response = wp_remote_get(
            esc_url_raw($settings->jwks_uri),
            array(
                'timeout' => 15,
                'sslverify' => true,
            )
        );

        if (is_wp_error($jwks_response)) {
            throw new DomainException(
                'Failed to fetch JWKS: ' . $jwks_response->get_error_message()
            );
        }

        $jwks_body = wp_remote_retrieve_body($jwks_response);
        $jwks = json_decode($jwks_body, true);

        if (!is_array($jwks) || empty($jwks['keys']) || !is_array($jwks['keys'])) {
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

        $token_nonce = isset($jwt->nonce) ? (string) $jwt->nonce : '';
        if ($token_nonce !== $antiforgery_id) {
            throw new DomainException(
                sprintf('Nonce mismatch. Expecting %s', esc_html($antiforgery_id))
            );
        }

        return $jwt;
    }
}