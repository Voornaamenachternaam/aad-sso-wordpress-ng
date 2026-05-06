<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\HttpFactory;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
use Symfony\Component\HttpClient\HttpClient;
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
        $response = $this->http_client->request($request->getMethod(), (string) $request->getUri(), [
            'headers' => $this->getFlattenedHeaders($request),
            'body' => $request->getBody()->getContents(),
        ]);

        $statusCode = $response->getStatusCode();
        /** @var string $reasonPhrase */
        $reasonPhrase = $response->getInfo('reason_phrase') ?: '';
        $responseHeaders = [];
        foreach ($response->getHeaders() as $name => $values) {
            $responseHeaders[$name] = $values;
        }

        return new class($statusCode, $reasonPhrase, $responseHeaders, $response->getContent(false)) implements ResponseInterface {
            private int $statusCode;
            private string $reasonPhrase;
            /** @var array<string, array<string>> */
            private array $headers;
            private string $body;
            private string $protocolVersion;

            /**
             * @param array<string, array<string>> $headers
             */
            public function __construct(int $statusCode, string $reasonPhrase, array $headers, string $body)
            {
                $this->statusCode = $statusCode;
                $this->reasonPhrase = $reasonPhrase;
                $this->headers = $headers;
                $this->body = $body;
                $this->protocolVersion = '1.1';
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
                return $this->protocolVersion;
            }

            public function withProtocolVersion(string $version): self
            {
                $clone = clone $this;
                $clone->protocolVersion = $version;
                return $clone;
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

                    public function getSize(): int
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
                        return $result;
                    }

                    public function getContents(): string
                    {
                        return substr($this->content, $this->position);
                    }

                    /**
                     * @return array<string, mixed>|mixed
                     */
                    public function getMetadata(?string $key = null): mixed
                    {
                        $metadata = [
                            'seekable' => true,
                            'eof' => $this->eof(),
                        ];

                        if (null === $key) {
                            return $metadata;
                        }

                        return $metadata[$key] ?? null;
                    }
                };
            }

            public function withBody(StreamInterface $body): self
            {
                $clone = clone $this;
                $clone->body = $body->getContents();
                return $clone;
            }
        };
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    private function createRequestOptions(string $method, string $url, array $options): array
    {
        if (!empty($options['query'])) {
            $separator = (strpos($url, '?') !== false) ? '&' : '?';
            $url .= $separator . http_build_query(self::normalizeQueryParams($options['query']));
            unset($options['query']);
        }

        return $options;
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
        $options = $this->createRequestOptions('GET', $url, $options);
        $request = $this->createRequest('GET', $url, $options);
        return $this->sendRequest($request);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function post(string $url, array $options = []): ResponseInterface
    {
        $options = $this->createRequestOptions('POST', $url, $options);
        $request = $this->createRequest('POST', $url, $options);
        return $this->sendRequest($request);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function createRequest(string $method, string $url, array $options = []): RequestInterface
    {
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
     * @param mixed $query
     * @return array<string, mixed>
     */
    private static function normalizeQueryParams(mixed $query): array
    {
        if (!\is_array($query)) {
            return [];
        }

        /** @var array<string, mixed> $queryArray */
        $queryArray = $query;
        $result = [];
        foreach ($queryArray as $key => $value) {
            if (\is_array($value)) {
                // Preserve arrays for http_build_query to generate repeated keys (e.g., key[]=val1&key[]=val2)
                $result[$key] = $value;
            } elseif (\is_string($value)) {
                $result[$key] = $value;
            } elseif (\is_scalar($value)) {
                $result[$key] = (string) $value;
            }
        }

        /** @var array<string, array<mixed>|string> */
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
                $normalized_headers[$name] = [\is_string($values) ? $values : ''];
            }
        }

        return new class($status, '', $normalized_headers, $body) implements ResponseInterface {
            private int $statusCode;
            /** @var array<string, array<string>> */
            private array $headers;
            private string $body;
            private string $reasonPhrase = '';
            private string $protocolVersion;

            /**
             * @param array<string, array<string>> $headers
             */
            public function __construct(int $status, string $reasonPhrase, array $headers, string $body)
            {
                $this->statusCode = $status;
                $this->reasonPhrase = $reasonPhrase;
                $this->headers = $headers;
                $this->body = $body;
                $this->protocolVersion = '1.1';
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
                return $this->protocolVersion;
            }

            public function withProtocolVersion(string $version): self
            {
                $clone = clone $this;
                $clone->protocolVersion = $version;
                return $clone;
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

                    public function getSize(): int
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
                        return $result;
                    }

                    public function getContents(): string
                    {
                        return substr($this->content, $this->position);
                    }

                    /**
                     * @return array<string, mixed>|mixed
                     */
                    public function getMetadata(?string $key = null): mixed
                    {
                        $metadata = [
                            'seekable' => true,
                            'eof' => $this->eof(),
                        ];

                        if (null === $key) {
                            return $metadata;
                        }

                        return $metadata[$key] ?? null;
                    }
                };
            }

            public function withBody(StreamInterface $body): self
            {
                $clone = clone $this;
                $clone->body = $body->getContents();
                return $clone;
            }
        };
    }
}