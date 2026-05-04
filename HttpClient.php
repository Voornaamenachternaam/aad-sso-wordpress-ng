<?php

/**
 * HTTP Client wrapper implementing PSR-18 standard.
 *
 * Provides a consistent HTTP client interface for making requests
 * to Microsoft Entra ID and Graph API endpoints.
 *
 * @package AADSSO
 */
declare(strict_types=1);

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpClient\Psr18Client;
use Symfony\Contracts\HttpClient\HttpClientInterface;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * PSR-18 HTTP Client wrapper.
 *
 * Wraps Symfony HttpClient to provide PSR-18 compatible interface.
 * Used for Microsoft Entra ID and Graph API communications.
 */
class AADSSO_HttpClient implements ClientInterface
{
    /** @var HttpClientInterface */
    private HttpClientInterface $http_client;

    /** @var Psr18Client */
    private Psr18Client $psr18_client;

    /** @var self|null Singleton instance */
    private static ?self $instance = null;

    /**
     * Constructor.
     *
     * @param HttpClientInterface|null $http_client Optional custom HTTP client.
     */
    public function __construct(?HttpClientInterface $http_client = null)
    {
        if ($http_client !== null) {
            $this->http_client = $http_client;
        } else {
            // Create default HTTP client with sensible defaults
            $this->http_client = \Symfony\Component\HttpClient\HttpClient::create(array(
                'timeout' => 30,
                'verify_peer' => true,
                'verify_host' => true,
            ));
        }

        $this->psr18_client = new Psr18Client($this->http_client);
    }

    /**
     * Get singleton instance.
     */
    public static function get_instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Send a PSR-7 request.
     *
     * @param RequestInterface $request The PSR-7 request to send.
     * @return ResponseInterface The PSR-7 response.
     * @throws \Psr\Http\Client\ClientExceptionInterface If an error occurs.
     */
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        return $this->psr18_client->sendRequest($request);
    }

    /**
     * Create and send a GET request.
     *
     * @param string $url The URL to request.
     * @param array<string, mixed> $options Request options (headers, query params, etc.).
     * @return ResponseInterface The PSR-7 response.
     * @throws \Psr\Http\Client\ClientExceptionInterface If an error occurs.
     */
    public function get(string $url, array $options = array()): ResponseInterface
    {
        $request = $this->createRequest('GET', $url, $options);
        return $this->sendRequest($request);
    }

    /**
     * Create and send a POST request.
     *
     * @param string $url The URL to request.
     * @param array<string, mixed> $options Request options (headers, body, etc.).
     * @return ResponseInterface The PSR-7 response.
     * @throws \Psr\Http\Client\ClientExceptionInterface If an error occurs.
     */
    public function post(string $url, array $options = array()): ResponseInterface
    {
        $request = $this->createRequest('POST', $url, $options);
        return $this->sendRequest($request);
    }

    /**
     * Create a PSR-7 request.
     *
     * @param string $method HTTP method (GET, POST, etc.).
     * @param string $url The URL to request.
     * @param array<string, mixed> $options Request options:
     *   - headers: array<string, string|string[]>
     *   - body: string|array|resource
     *   - query: array<string, mixed> (appended to URL as query params)
     * @return RequestInterface The PSR-7 request.
     */
    public function createRequest(string $method, string $url, array $options = array()): RequestInterface
    {
        // Handle query parameters
        if (!empty($options['query'])) {
            $separator = (strpos($url, '?') !== false) ? '&' : '?';
            $url .= $separator . http_build_query($options['query']);
            unset($options['query']);
        }

        // Get PSR-7 factory from the Psr18Client
        $requestFactory = $this->psr18_client->getRequestFactory();
        if ($requestFactory === null) {
            throw new \RuntimeException('Request factory not available');
        }

        $headers = $options['headers'] ?? array();
        $body = $options['body'] ?? '';

        // Handle array body (form data)
        if (is_array($body)) {
            $body = http_build_query($body);
            if (!isset($headers['Content-Type'])) {
                $headers['Content-Type'] = 'application/x-www-form-urlencoded';
            }
        }

        $request = $requestFactory->createRequest($method, $url);

        // Add headers
        $uri = $request->getUri();
        foreach ($headers as $name => $value) {
            $uri = $uri->withHeader($name, $value);
        }
        $request = $request->withUri($uri);

        // Add body if applicable
        if (!empty($body) && in_array($method, array('POST', 'PUT', 'PATCH'), true)) {
            $request = $request->withBody(
                $this->psr18_client->getStreamFactory()->createStream($body)
            );
        }

        return $request;
    }

    /**
     * Get the underlying Symfony HTTP client.
     *
     * @return HttpClientInterface The HTTP client instance.
     */
    public function get_http_client(): HttpClientInterface
    {
        return $this->http_client;
    }

    /**
     * Create a PSR-7 Response from a response body array.
     *
     * Useful for testing and mocking.
     *
     * @param array<string, mixed> $data Response data (body, status, headers).
     * @return ResponseInterface A PSR-7 response.
     */
    public static function create_response(array $data): ResponseInterface
    {
        $factory = new \Nyholm\Psr7\Factory\Psr17Factory();
        $status = $data['status'] ?? 200;
        $headers = $data['headers'] ?? array();
        $body = is_string($data['body'] ?? null) ? $data['body'] : json_encode($data['body'] ?? '');

        return $factory->createResponse($status, '', $headers)
            ->withBody($factory->createStream($body));
    }
}