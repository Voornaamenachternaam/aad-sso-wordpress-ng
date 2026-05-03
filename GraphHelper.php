<?php

declare(strict_types=1);

use Http\Client\Common\HttpMethodsClient;
use Http\Client\Common\Plugin\AddHostPlugin;
use Http\Discovery\Psr17Discovery;
use Http\Discovery\Psr18Discovery;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\UriFactoryInterface;

class AADSSO_GraphHelper
{
    public static ?AADSSO_Settings $settings = null;
    public const GRAPH_VERSION = 'v1.0';

    private static ?HttpMethodsClient $http_client = null;

    public static function get_base_url(): string
    {
        $endpoint = self::$settings->graph_endpoint ?? 'https://graph.microsoft.com';
        $version = self::$settings->graph_version ?? self::GRAPH_VERSION;
        return trailingslashit($endpoint) . $version;
    }

    public static function get_http_client(): HttpMethodsClient
    {
        if (self::$http_client === null) {
            $http_client = Psr18Discovery::findClient();
            $uri_factory = Psr17Discovery::findUriFactory();

            $base_uri = $uri_factory->createUri(self::get_base_url());
            $add_host_plugin = new AddHostPlugin($base_uri);

            self::$http_client = new HttpMethodsClient(
                $http_client,
                Psr17Discovery::findRequestFactory()
            );
        }

        return self::$http_client;
    }

    public static function set_http_client(HttpMethodsClient $client): void
    {
        self::$http_client = $client;
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
        $query_params = http_build_query($query_params);
        $url = $url . '?' . $query_params;

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
        $query_params = http_build_query($query_params);
        $url = $url . '?' . $query_params;
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
            return null;
        }

        if (null === $response) {
            return null;
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

    public static function is_sdk_available(): bool
    {
        return class_exists('\Microsoft\Graph\Graph');
    }

    public static function create_graph_client(): ?\Microsoft\Graph\Graph
    {
        if (!self::is_sdk_available()) {
            return null;
        }

        $token_type = 'Bearer';
        $access_token = '';

        if (session_status() === PHP_SESSION_ACTIVE) {
            $token_type = (string) ($_SESSION['aadsso_token_type'] ?? 'Bearer');
            $access_token = (string) ($_SESSION['aadsso_access_token'] ?? '');
        }

        $graph = new \Microsoft\Graph\Graph();
        $graph->setAccessToken($token_type . ' ' . $access_token);

        return $graph;
    }
}