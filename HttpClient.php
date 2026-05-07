<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

if (!\defined('ABSPATH')) {
    exit;
}

class AADSSO_HttpClient implements ClientInterface
{
    /** @var HttpClientInterface */
    private HttpClientInterface $http_client;
    /** @var RequestFactoryInterface */
    private RequestFactoryInterface $request_factory;
    /** @var StreamFactoryInterface */
    private StreamFactoryInterface $stream_factory;
    /** @var self|null */
    private static ?self $instance = null;

    public function __construct(?HttpClientInterface $http_client = null)
    {
        if (null !== $http_client) {
            $this->http_client = $http_client;
        } else {
            $this->http_client = HttpClient::create([
                'timeout' => 30,
                'verify_peer' => true,
                'verify_host' => true,
            ]);
        }

        $httpFactory = new HttpFactory();
        $this->request_factory = $httpFactory;
        $this->stream_factory = $httpFactory;
    }

    public static function get_instance(): self
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        try {
            $response = $this->http_client->request($request->getMethod(), (string) $request->getUri(), [
                'headers' => $this->getFlattenedHeaders($request),
                'body' => (string) $request->getBody(),
            ]);

            $statusCode = $response->getStatusCode();
            $responseHeaders = [];
            foreach ($response->getHeaders(false) as $name => $values) {
                $responseHeaders[$name] = $values;
            }

            return new GuzzleResponse($statusCode, $responseHeaders, $response->getContent(false));
        } catch (TransportExceptionInterface $e) {
            throw new AADSSO_HttpClientNetworkException($e->getMessage(), $request, $e);
        }
    }

    /**
     * @return array<string, string>
     */
    private function getFlattenedHeaders(RequestInterface $request): array
    {
        $flattened = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headerValue = implode(', ', $values);
            /** @var string $headerValue */
            $flattened[$name] = $headerValue;
        }
        /** @var array<string, string> */
        return $flattened;
    }

    /**
     * @param array<string, mixed> $options
     */
    public function get(string $url, array $options = []): ResponseInterface
    {
        $request = $this->createRequest('GET', $url, $options);
        return $this->sendRequest($request);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function post(string $url, array $options = []): ResponseInterface
    {
        $request = $this->createRequest('POST', $url, $options);
        return $this->sendRequest($request);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function createRequest(string $method, string $url, array $options = []): RequestInterface
    {
        if (!empty($options['query'])) {
            $separator = (strpos($url, '?') !== false) ? '&' : '?';
            $url .= $separator . self::buildQueryString(self::normalizeQueryParams($options['query']));
            unset($options['query']);
        }

        /** @var array<string, string|array<string>> $headers */
        $headers = $options['headers'] ?? [];
        $body = $options['body'] ?? '';

        $request = $this->request_factory->createRequest($method, $url);

        foreach ($headers as $name => $value) {
            if (\is_array($value)) {
                foreach ($value as $singleValue) {
                    /** @var string $singleValue */
                    $request = $request->withAddedHeader($name, $singleValue);
                }
            } else {
                /** @var string $value */
                $request = $request->withHeader($name, $value);
            }
        }

        if (!empty($body) && \in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            /** @var string $body */
            $stream = $this->stream_factory->createStream($body);
            $request = $request->withBody($stream);
        }

        return $request;
    }

    /**
     * @param array<string, array<int, string>|string> $params
     */
    private static function buildQueryString(array $params): string
    {
        $parts = [];
        foreach ($params as $key => $value) {
            $encodedKey = \rawurlencode((string) $key);
            if (\is_array($value)) {
                foreach ($value as $item) {
                    $parts[] = $encodedKey . '=' . \rawurlencode(self::scalarToString($item));
                }
            } else {
                $parts[] = $encodedKey . '=' . \rawurlencode(self::scalarToString($value));
            }
        }

        return implode('&', $parts);
    }

    /**
     * @param scalar $value
     */
    private static function scalarToString(mixed $value): string
    {
        if (\is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        return (string) $value;
    }

    /**
     * @param mixed $query
     * @return array<string, array<int, string>|string>
     */
    private static function normalizeQueryParams(mixed $query): array
    {
        if (!\is_array($query)) {
            return [];
        }

        /** @var array<string, mixed> $queryArray */
        $queryArray = $query;
        /** @var array<string, array<int, string>|string> $result */
        $result = [];
        foreach ($queryArray as $key => $value) {
            if (\is_array($value)) {
                // Flatten arrays into repeated keys (e.g., key=val1&key=val2)
                // instead of bracketed notation (e.g., key[0]=val1&key[1]=val2)
                /** @var array<int, string> $values */
                $values = [];
                foreach ($value as $item) {
                    if (\is_scalar($item)) {
                        $values[] = self::scalarToString($item);
                    }
                }
                // Only add if we have values after filtering
                if (!empty($values)) {
                    /** @var string $key */
                    $result[$key] = $values;
                }
            } elseif (\is_scalar($value)) {
                /** @var string $key */
                $result[$key] = self::scalarToString($value);
            }
        }

        /** @var array<string, array<int, string>|string> */
        return $result;
    }

    public function get_http_client(): HttpClientInterface
    {
        return $this->http_client;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function create_response(array $data): ResponseInterface
    {
        $status = isset($data['status']) && \is_int($data['status']) ? $data['status'] : 200;
        $headers = isset($data['headers']) && \is_array($data['headers']) ? $data['headers'] : [];
        $body_raw = $data['body'] ?? '';
        /** @var string */
        $body = \is_string($body_raw) ? $body_raw : (json_encode($body_raw) ?: '');

        // Normalize headers to array<string, array<string>>
        /** @var array<string, array<string>> $normalized_headers */
        $normalized_headers = [];
        foreach ($headers as $name => $values) {
            /** @var string $name */
            if (\is_array($values)) {
                /** @var list<scalar> $flattenValues */
                $flattenValues = array_values($values);
                /** @var list<string> $stringValues */
                $stringValues = [];
                foreach ($flattenValues as $fv) {
                    $stringValues[] = (string) $fv;
                }
                $normalized_headers[$name] = $stringValues;
            } else {
                $normalized_headers[$name] = [
                    \is_string($values) ? $values : (\is_scalar($values) ? (string) $values : ''),
                ];
            }
        }

        return new GuzzleResponse($status, $normalized_headers, $body);
    }
}

class AADSSO_HttpClientNetworkException extends \RuntimeException implements NetworkExceptionInterface
{
    private RequestInterface $request;

    public function __construct(string $message, RequestInterface $request, \Throwable $previous)
    {
        parent::__construct($message, 0, $previous);
        $this->request = $request;
    }

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }
}