<?php

/**
 * Microsoft Graph API helper class.
 *
 * Provides methods for interacting with Microsoft Graph API endpoints
 * using PSR-18 HTTP client for standardized HTTP communication.
 */
declare(strict_types=1);

use Psr\Http\Message\ResponseInterface;

/**
 * Microsoft Graph API helper class.
 */
class AADSSO_GraphHelper
{
    public const GRAPH_VERSION = 'v1.0';

    /** @var AADSSO_Settings|null Static settings reference */
    public static ?AADSSO_Settings $settings = null;

    /** @var AADSSO_HttpClient|null HTTP client instance */
    private static ?AADSSO_HttpClient $http_client = null;

    /**
     * Get the Graph API base URL.
     *
     * @return string
     */
    public static function get_base_url(): string
    {
        $endpoint = self::$settings->graph_endpoint ?? 'https://graph.microsoft.com';
        $version = self::$settings->graph_version ?? self::GRAPH_VERSION;

        return trailingslashit($endpoint) . $version;
    }

    /**
     * Check if a user is a member of the specified groups.
     *
     * @param string $user_id The user ID (object ID from Entra ID).
     * @param array<string> $group_ids Array of group IDs to check membership.
     * @return object|WP_Error Response object or WP_Error on failure.
     */
    public static function user_check_member_groups(string $user_id, array $group_ids): object|WP_Error
    {
        $url = self::get_base_url() . '/users/' . rawurlencode($user_id) . '/checkMemberGroups';

        return self::post_request($url, [], ['groupIds' => $group_ids]);
    }

    /**
     * Get a user by their ID.
     *
     * @param string $user_id The user ID (object ID from Entra ID).
     * @return object|WP_Error User object or WP_Error on failure.
     */
    public static function get_user(string $user_id): object|WP_Error
    {
        $url = self::get_base_url() . '/users/' . rawurlencode($user_id);

        return self::get_request($url);
    }

    /**
     * Make a GET request to the Graph API.
     *
     * @param string $url The URL to request.
     * @param array<string, mixed> $query_params Query parameters to append to URL.
     * @return object|WP_Error Response object or WP_Error on failure.
     */
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

    /**
     * Make a POST request to the Graph API.
     *
     * @param string $url The URL to request.
     * @param array<string, mixed> $query_params Query parameters to append to URL.
     * @param array<string, mixed> $data Request body data.
     * @return object|WP_Error Response object or WP_Error on failure.
     */
    public static function post_request(string $url, array $query_params = [], array $data = []): object|WP_Error
    {
        if (!empty($query_params)) {
            $url = $url . '?' . http_build_query($query_params);
        }
        $payload = wp_json_encode($data);

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

    /**
     * Get the HTTP client instance.
     *
     * @return AADSSO_HttpClient
     */
    private static function get_http_client(): AADSSO_HttpClient
    {
        if (null === self::$http_client) {
            self::$http_client = AADSSO_HttpClient::get_instance();
        }

        return self::$http_client;
    }

    /**
     * Parse and log a PSR-7 response.
     *
     * @param ResponseInterface $response The PSR-7 response.
     * @return object|WP_Error The decoded response body or WP_Error on failure.
     */
    private static function parse_and_log_response(ResponseInterface $response): object|WP_Error
    {
        $status_code = $response->getStatusCode();
        /** @var array<string, string> $response_headers */
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

        /** @var mixed $decoded */
        $decoded = json_decode($response_body, true);

        if (\JSON_ERROR_NONE !== json_last_error()) {
            AADSSO_Logger::log_error('Graph API response JSON decode error: ' . json_last_error_msg());

            return new WP_Error('invalid_json_response', 'Graph API response could not be decoded');
        }

        /** @var object */
        return (object) $decoded;
    }

    /**
     * Get the required headers for Graph API requests.
     *
     * @return array<string, string>
     */
    private static function get_required_headers_and_settings(): array
    {
        $token_type = 'Bearer';
        $access_token = '';

        if (\PHP_SESSION_ACTIVE === session_status()) {
            /** @var string $session_token_type */
            $session_token_type = $_SESSION['aadsso_token_type'] ?? 'Bearer';
            /** @var string $session_access_token */
            $session_access_token = $_SESSION['aadsso_access_token'] ?? '';
            $token_type = $session_token_type;
            $access_token = $session_access_token;
        }

        return [
            'Authorization' => $token_type . ' ' . $access_token,
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
            'Prefer' => 'return-content',
        ];
    }
}