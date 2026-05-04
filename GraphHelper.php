<?php

/**
 * Microsoft Graph API helper class.
 *
 * Provides methods for interacting with Microsoft Graph API endpoints
 * using PSR-18 HTTP client for standardized HTTP communication.
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

    /** @var AADSSO_HttpClient|null HTTP client instance */
    private static ?AADSSO_HttpClient $http_client = null;

    public const GRAPH_VERSION = 'v1.0';

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

        $options = array(
            'headers' => self::get_required_headers_and_settings(),
        );

        try {
            $response = self::get_http_client()->get($url, $options);
            return self::parse_and_log_response($response);
        } catch (\Throwable $e) {
            AADSSO_Logger::log_error('Graph API GET request failed: ' . $e->getMessage());
            return new WP_Error('http_request_failed', $e->getMessage());
        }
    }

    public static function post_request(string $url, array $query_params = array(), array $data = array()): mixed
    {
        if (!empty($query_params)) {
            $url = $url . '?' . http_build_query($query_params);
        }
        $payload = wp_json_encode($data);

        AADSSO_Logger::log_debug('POST ' . $url, 50);
        AADSSO_Logger::log_debug($payload, 99);

        $options = array(
            'body' => $payload,
            'headers' => self::get_required_headers_and_settings(),
        );

        try {
            $response = self::get_http_client()->post($url, $options);
            return self::parse_and_log_response($response);
        } catch (\Throwable $e) {
            AADSSO_Logger::log_error('Graph API POST request failed: ' . $e->getMessage());
            return new WP_Error('http_request_failed', $e->getMessage());
        }
    }

    /**
     * Parse and log a PSR-7 response.
     *
     * @param \Psr\Http\Message\ResponseInterface $response The PSR-7 response.
     * @return mixed The decoded response body or WP_Error on failure.
     */
    private static function parse_and_log_response(\Psr\Http\Message\ResponseInterface $response): mixed
    {
        $status_code = $response->getStatusCode();
        $response_headers = array();
        foreach ($response->getHeaders() as $name => $values) {
            $response_headers[$name] = implode(', ', $values);
        }
        $response_body = $response->getBody()->getContents();

        AADSSO_Logger::log_debug('Response headers: ' . wp_json_encode($response_headers), 99);
        AADSSO_Logger::log_debug('Response body: ' . wp_json_encode($response_body), 50);

        if ($status_code >= 400) {
            AADSSO_Logger::log_error('Graph API Error: HTTP ' . $status_code . ' - ' . $response_body);
            return new WP_Error(
                'http_error',
                'Graph API request failed with HTTP ' . $status_code
            );
        }

        $decoded = json_decode($response_body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            AADSSO_Logger::log_error('Graph API response JSON decode error: ' . json_last_error_msg());
            return new WP_Error('invalid_json_response', 'Graph API response could not be decoded');
        }

        return (object) $decoded;
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