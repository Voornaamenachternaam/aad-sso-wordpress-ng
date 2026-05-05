<?php

declare(strict_types=1);

use Psr\Http\Message\ResponseInterface;

class AADSSO_GraphHelper
{
    public const GRAPH_VERSION = 'v1.0';

    public static ?AADSSO_Settings $settings = null;

    private static AADSSO_HttpClient $http_client;

    public static function get_base_url(): string
    {
        $endpoint = self::$settings->graph_endpoint ?? 'https://graph.microsoft.com';
        $version = self::$settings->graph_version ?? self::GRAPH_VERSION;

        return trailingslashit($endpoint) . $version;
    }

    public static function user_check_member_groups(string $user_id, array $group_ids): object|WP_Error
    {
        $url = self::get_base_url() . '/users/' . rawurlencode($user_id) . '/checkMemberGroups';

        return self::post_request($url, [], ['groupIds' => $group_ids]);
    }

    public static function get_user(string $user_id): object|WP_Error
    {
        $url = self::get_base_url() . '/users/' . rawurlencode($user_id);

        return self::get_request($url);
    }

    public static function get_request(string $url, array $query_params = []): object|WP_Error
    {
        if (!empty($query_params)) {
            $url = $url . '?' . http_build_query($query_params);
        }

        if (\PHP_SESSION_ACTIVE === session_status()) {
            $_SESSION['aadsso_last_request'] = [
                'method' => 'GET',
                'url' => $url,
            ];
        }

        AADSSO_Logger::log_debug('GET ' . $url, 50);

        $options = [
            'headers' => self::get_required_headers_and_settings(),
        ];

        try {
            $response = self::get_http_client()->get($url, $options);

            return self::parse_and_log_response($response);
        } catch (\Throwable $e) {
            AADSSO_Logger::log_error('Graph API GET request failed: ' . $e->getMessage());

            return new WP_Error('http_request_failed', $e->getMessage());
        }
    }

    public static function post_request(string $url, array $query_params = [], array $data = []): object|WP_Error
    {
        if (!empty($query_params)) {
            $url = $url . '?' . http_build_query($query_params);
        }
        $payload = (string) wp_json_encode($data);

        AADSSO_Logger::log_debug('POST ' . $url, 50);
        AADSSO_Logger::log_debug($payload, 99);

        $options = [
            'body' => $payload,
            'headers' => self::get_required_headers_and_settings(),
        ];

        try {
            $response = self::get_http_client()->post($url, $options);

            return self::parse_and_log_response($response);
        } catch (\Throwable $e) {
            AADSSO_Logger::log_error('Graph API POST request failed: ' . $e->getMessage());

            return new WP_Error('http_request_failed', $e->getMessage());
        }
    }

    private static function get_http_client(): AADSSO_HttpClient
    {
        if (!isset(self::$http_client)) {
            self::$http_client = AADSSO_HttpClient::get_instance();
        }

        return self::$http_client;
    }

    private static function parse_and_log_response(ResponseInterface $response): object|WP_Error
    {
        $status_code = $response->getStatusCode();
        $response_headers = [];
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

        if (!\is_array($decoded)) {
            AADSSO_Logger::log_error('Graph API response JSON decode error: ' . json_last_error_msg());

            return new WP_Error('invalid_json_response', 'Graph API response could not be decoded');
        }

        return (object) $decoded;
    }

    private static function get_required_headers_and_settings(): array
    {
        $token_type = 'Bearer';
        $access_token = '';

        if (\PHP_SESSION_ACTIVE === session_status()) {
            $session_token_type = $_SESSION['aadsso_token_type'] ?? 'Bearer';
            $session_access_token = $_SESSION['aadsso_access_token'] ?? '';
            $token_type = (string) $session_token_type;
            $access_token = (string) $session_access_token;
        }

        return [
            'Authorization' => $token_type . ' ' . $access_token,
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
            'Prefer' => 'return-content',
        ];
    }
}