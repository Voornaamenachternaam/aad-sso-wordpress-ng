<?php

declare(strict_types=1);

use Psr\Http\Message\ResponseInterface;

if (!\defined('ABSPATH')) {
    exit;
}

class GraphHelper
{
    public const GRAPH_VERSION = 'v1.0';

    public static ?AADSSO_Settings $settings = null;

    private static ?AADSSO_HttpClient $http_client = null;

    public static function get_base_url(): string
    {
        $endpoint = self::$settings->graph_endpoint ?? 'https://graph.microsoft.com';
        $version = self::$settings->graph_version ?? self::GRAPH_VERSION;

        return trailingslashit($endpoint) . $version;
    }

    /**
     * @param list<string> $group_ids
     */
    public static function user_check_member_groups(string $user_id, array $group_ids): WP_Error|stdClass
    {
        $url = self::get_base_url() . '/users/' . rawurlencode($user_id) . '/checkMemberGroups';

        return self::post_request($url, [], ['groupIds' => $group_ids]);
    }

    public static function get_user(string $user_id): WP_Error|stdClass
    {
        $url = self::get_base_url() . '/users/' . rawurlencode($user_id);

        return self::get_request($url);
    }

    /**
     * @param array<string, mixed> $query_params
     */
    public static function get_request(string $url, array $query_params = []): WP_Error|stdClass
    {
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

        if (!empty($query_params)) {
            $options['query'] = $query_params;
        }

        try {
            $response = self::get_http_client()->get($url, $options);

            return self::parse_and_log_response($response);
        } catch (Throwable $e) {
            AADSSO_Logger::log_error('Graph API GET request failed: ' . $e->getMessage());

            return new WP_Error('http_request_failed', $e->getMessage());
        }
    }

    /**
     * @param array<string, mixed> $query_params
     * @param array<string, mixed> $data
     */
    public static function post_request(string $url, array $query_params = [], array $data = []): WP_Error|stdClass
    {
        $payload = (string) wp_json_encode($data);

        AADSSO_Logger::log_debug('POST ' . $url, 50);
        AADSSO_Logger::log_debug($payload, 99);

        $options = [
            'body' => $payload,
            'headers' => self::get_required_headers_and_settings(),
        ];

        if (!empty($query_params)) {
            $options['query'] = $query_params;
        }

        try {
            $response = self::get_http_client()->post($url, $options);

            return self::parse_and_log_response($response);
        } catch (Throwable $e) {
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

    private static function parse_and_log_response(ResponseInterface $response): WP_Error|stdClass
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

    /**
     * @return array<string, string>
     */
    private static function get_required_headers_and_settings(): array
    {
        $token_type = 'Bearer';
        $access_token = '';

        if (\PHP_SESSION_ACTIVE === session_status()) {
            $session_token_type = $_SESSION['aadsso_token_type'] ?? 'Bearer';
            $session_access_token = $_SESSION['aadsso_access_token'] ?? '';
            $token_type = \is_string($session_token_type) ? $session_token_type : 'Bearer';
            $access_token = \is_string($session_access_token) ? $session_access_token : '';
        }

        return [
            'Authorization' => $token_type . ' ' . $access_token,
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
            'Prefer' => 'return-content',
        ];
    }
}

class_alias(GraphHelper::class, 'AADSSO_GraphHelper');
