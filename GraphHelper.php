<?php

/**
 * Microsoft Graph API helper class.
 *
 * Provides methods for interacting with Microsoft Graph API endpoints.
 *
 * @package AADSSO
 */
declare(strict_types=1);

/**
 * Microsoft Graph API helper class.
 *
 * @package AADSSO
 */
class AADSSO_GraphHelper
{
    /** @var AADSSO_Settings|null Static settings reference */
    public static ?AADSSO_Settings $settings = null;

    public const GRAPH_VERSION = 'v1.0';

    public static function get_base_url(): string
    {
        $endpoint = self::$settings->graph_endpoint ?? 'https://graph.microsoft.com';
        $version = self::$settings->graph_version ?? self::GRAPH_VERSION;
        return trailingslashit($endpoint) . $version;
    }

    public static function user_check_member_groups(string $user_id, array $group_ids): mixed
    {
        $url = self::get_base_url() . '/users/' . rawurlencode($user_id) . '/checkMemberGroups';
        return self::post_request($url, array(), array('groupIds' => $group_ids));
    }

    public static function get_user(string $user_id): mixed
    {
        $url = self::get_base_url() . '/users/' . rawurlencode($user_id);
        return self::get_request($url);
    }

    public static function get_request(string $url, array $query_params = array()): mixed
    {
        if (!empty($query_params)) {
            $url = $url . '?' . http_build_query($query_params);
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION['aadsso_last_request'] = array(
                'method' => 'GET',
                'url' => $url,
            );
        }

        AADSSO_Logger::log_debug('GET ' . $url, 50);

        $response = wp_remote_get(
            esc_url_raw($url),
            array(
                'headers' => self::get_required_headers_and_settings(),
                'timeout' => 30,
                'sslverify' => true,
            )
        );

        return self::parse_and_log_response($response);
    }

    public static function post_request(string $url, array $query_params = array(), array $data = array()): mixed
    {
        if (!empty($query_params)) {
            $url = $url . '?' . http_build_query($query_params);
        }
        $payload = wp_json_encode($data);

        AADSSO_Logger::log_debug('POST ' . $url, 50);
        AADSSO_Logger::log_debug($payload, 99);

        $response = wp_remote_post(
            esc_url_raw($url),
            array(
                'body' => $payload,
                'headers' => self::get_required_headers_and_settings(),
                'timeout' => 30,
                'sslverify' => true,
            )
        );

        return self::parse_and_log_response($response);
    }

    private static function parse_and_log_response(mixed $response): mixed
    {
        if (is_wp_error($response)) {
            AADSSO_Logger::log_error(
                'Graph API Error: ' . $response->get_error_message()
            );
            return $response;
        }

        $response_headers = wp_remote_retrieve_headers($response);
        $response_body = wp_remote_retrieve_body($response);

        AADSSO_Logger::log_debug('Response headers: ' . wp_json_encode($response_headers), 99);
        AADSSO_Logger::log_debug('Response body: ' . wp_json_encode($response_body), 50);

        return json_decode($response_body);
    }

    private static function get_required_headers_and_settings(): array
    {
        $token_type = 'Bearer';
        $access_token = '';

        if (session_status() === PHP_SESSION_ACTIVE) {
            $token_type = (string) ($_SESSION['aadsso_token_type'] ?? 'Bearer');
            $access_token = (string) ($_SESSION['aadsso_access_token'] ?? '');
        }

        return array(
            'Authorization' => $token_type . ' ' . $access_token,
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
            'Prefer' => 'return-content',
        );
    }
}