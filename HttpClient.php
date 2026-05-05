<?php

/**
 * HTTP Client wrapper implementing PSR-18 standard.
 *
 * Provides a consistent HTTP client interface for making requests
 * to Microsoft Entra ID and Graph API endpoints.
 */
declare(strict_types=1);

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\Psr18Client;
use Symfony\Contracts\HttpClient\HttpClientInterface;

if (!\defined('ABSPATH')) {
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
        if (null !== $http_client) {
            $this->http_client = $http_client;
        } else {
            $this->http_client = HttpClient::create([
                'timeout' => 30,
                'verify_peer' => true,
                'verify_host' => true,
            ]);
        }

        $this->psr18_client = new Psr18Client($this->http_client);
    }

    /**
     * Get singleton instance.
     */
    public static function get_instance(): self
    {
        if (null === self::$instance) {
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
    public function get(string $url, array $options = []): ResponseInterface
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
    public function post(string $url, array $options = []): ResponseInterface
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
    public function createRequest(string $method, string $url, array $options = []): RequestInterface
    {
        if (!empty($options['query'])) {
            $separator = (strpos($url, '?') !== false) ? '&' : '?';
            $url .= $separator . http_build_query($options['query']);
            unset($options['query']);
        }

        $requestFactory = $this->psr18_client->getRequestFactory();
        if (null === $requestFactory) {
            throw new \RuntimeException('Request factory not available');
        }

        /** @var array<string, string|string[]> $headers */
        $headers = $options['headers'] ?? [];
        $body = $options['body'] ?? '';

        if (\is_array($body)) {
            $body = http_build_query($body);
            if (!isset($headers['Content-Type'])) {
                $headers['Content-Type'] = 'application/x-www-form-urlencoded';
            }
        }

        /** @var RequestInterface $request */
        $request = $requestFactory->createRequest($method, $url);

        foreach ($headers as $name => $value) {
            /** @var string $name */
            /** @var string|string[] $value */
            if (\is_array($value)) {
                foreach ($value as $single_value) {
                    /** @var string $single_value */
                    $request = $request->withAddedHeader($name, $single_value);
                }
            } else {
                /** @var string $value */
                $request = $request->withHeader($name, $value);
            }
        }

        if (!empty($body) && \in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            $streamFactory = $this->psr18_client->getStreamFactory();
            if (null !== $streamFactory) {
                /** @var StreamInterface $stream */
                $stream = $streamFactory->createStream($body);
                $request = $request->withBody($stream);
            }
        }

        return $request;
    }

    /**
     * Get the underlying Symfony HTTP client.
     *
     * @return HttpClientInterface
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
        $status = $data['status'] ?? 200;
        /** @var array<string, string|string[]> $headers */
        $headers = $data['headers'] ?? [];
        $body = is_string($data['body'] ?? null) ? $data['body'] : json_encode($data['body'] ?? '');

        return new class($status, $headers, $body) implements ResponseInterface {
            private int $statusCode;
            /** @var array<string, array<string>> */
            private array $headers;
            private string $body;
            private string $reasonPhrase = '';

            /**
             * @param int $status
             * @param array<string, string|string[]> $headers
             * @param string $body
             */
            public function __construct(int $status, array $headers, string $body)
            {
                $this->statusCode = $status;
                /** @var array<string, array<string>> $normalized_headers */
                $normalized_headers = [];
                foreach ($headers as $name => $values) {
                    if (\is_array($values)) {
                        $normalized_headers[$name] = $values;
                    } else {
                        $normalized_headers[$name] = [$values];
                    }
                }
                $this->headers = $normalized_headers;
                $this->body = $body;
            }

            public function getStatusCode(): int
            {
                return $this->statusCode;
            }

            public function withStatus(int $code, string $reasonPhrase = ''): self
            {
                $clone = clone $this;
                $clone->statusCode = $code;
                $clone->reasonPhrase = $reasonPhrase;
                return $clone;
            }

            public function getReasonPhrase(): string
            {
                return $this->reasonPhrase;
            }

            public function getProtocolVersion(): string
            {
                return '1.1';
            }

            public function withProtocolVersion(string $version): self
            {
                return clone $this;
            }

            /**
             * @return array<string, array<string>>
             */
            public function getHeaders(): array
            {
                return $this->headers;
            }

            public function hasHeader(string $name): bool
            {
                return isset($this->headers[$name]);
            }

            /**
             * @return array<string>
             */
            public function getHeader(string $name): array
            {
                return $this->headers[$name] ?? [];
            }

            public function getHeaderLine(string $name): string
            {
                return implode(', ', $this->getHeader($name));
            }

            /**
             * @param string $name
             * @param string|string[] $value
             */
            public function withHeader(string $name, $value): self
            {
                $clone = clone $this;
                if (\is_array($value)) {
                    $clone->headers[$name] = $value;
                } else {
                    $clone->headers[$name] = [$value];
                }
                return $clone;
            }

            /**
             * @param string $name
             * @param string|string[] $value
             */
            public function withAddedHeader(string $name, $value): self
            {
                $clone = clone $this;
                if (\is_array($value)) {
                    if (!isset($clone->headers[$name])) {
                        $clone->headers[$name] = [];
                    }
                    foreach ($value as $v) {
                        $clone->headers[$name][] = $v;
                    }
                } else {
                    if (!isset($clone->headers[$name])) {
                        $clone->headers[$name] = [];
                    }
                    $clone->headers[$name][] = $value;
                }
                return $clone;
            }

            public function withoutHeader(string $name): self
            {
                $clone = clone $this;
                unset($clone->headers[$name]);
                return $clone;
            }

            public function getBody(): StreamInterface
            {
                return new class($this->body) implements StreamInterface {
                    private string $content;
                    private int $position = 0;

                    public function __construct(string $content)
                    {
                        $this->content = $content;
                    }

                    public function __toString(): string
                    {
                        return $this->content;
                    }

                    public function close(): void
                    {
                        $this->position = 0;
                    }

                    public function detach(): mixed
                    {
                        return null;
                    }

                    public function getSize(): ?int
                    {
                        return \strlen($this->content);
                    }

                    public function tell(): int
                    {
                        return $this->position;
                    }

                    public function eof(): bool
                    {
                        return $this->position >= \strlen($this->content);
                    }

                    public function isSeekable(): bool
                    {
                        return true;
                    }

                    public function seek(int $offset, int $whence = SEEK_SET): void
                    {
                        switch ($whence) {
                            case SEEK_SET:
                                $this->position = $offset;
                                break;
                            case SEEK_CUR:
                                $this->position += $offset;
                                break;
                            case SEEK_END:
                                $this->position = \strlen($this->content) + $offset;
                                break;
                        }
                    }

                    public function rewind(): void
                    {
                        $this->position = 0;
                    }

                    public function isWritable(): bool
                    {
                        return false;
                    }

                    public function write(string $string): int
                    {
                        return 0;
                    }

                    public function isReadable(): bool
                    {
                        return true;
                    }

                    public function read(int $length): string
                    {
                        $result = substr($this->content, $this->position, $length);
                        $this->position += \strlen($result);
                        /** @var string */
                        return $result;
                    }

                    public function getContents(): string
                    {
                        return substr($this->content, $this->position);
                    }

                    /**
                     * @return array<string, mixed>
                     */
                    public function getMetadata(?string $key = null): array
                    {
                        if (null === $key) {
                            return [
                                'seekable' => true,
                                'eof' => $this->eof(),
                            ];
                        }

                        return match ($key) {
                            'seekable' => true,
                            'eof' => $this->eof(),
                            default => null,
                        };
                    }
                };
            }

            /**
             * @param StreamInterface $body
             */
            public function withBody(StreamInterface $body): self
            {
                $clone = clone $this;
                $clone->body = $body->getContents();
                return $clone;
            }
        };
    }
}