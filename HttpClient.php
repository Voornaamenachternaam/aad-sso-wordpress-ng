<?php

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

class AADSSO_HttpClient implements ClientInterface
{
    /** @var HttpClientInterface */
    private $http_client;

    /** @var Psr18Client */
    private $psr18_client;

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

        $this->psr18_client = new Psr18Client($this->http_client);
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
        return $this->psr18_client->sendRequest($request);
    }

    public function get(string $url, array $options = []): ResponseInterface
    {
        $request = $this->createRequest('GET', $url, $options);

        return $this->sendRequest($request);
    }

    public function post(string $url, array $options = []): ResponseInterface
    {
        $request = $this->createRequest('POST', $url, $options);

        return $this->sendRequest($request);
    }

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

        $headers = $options['headers'] ?? [];
        $body = $options['body'] ?? '';

        if (\is_array($body)) {
            $body = http_build_query($body);
            if (!isset($headers['Content-Type'])) {
                $headers['Content-Type'] = 'application/x-www-form-urlencoded';
            }
        }

        $request = $requestFactory->createRequest($method, $url);

        foreach ($headers as $name => $value) {
            if (\is_array($value)) {
                foreach ($value as $single_value) {
                    $request = $request->withAddedHeader($name, $single_value);
                }
            } else {
                $request = $request->withHeader($name, $value);
            }
        }

        if (!empty($body) && \in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            $streamFactory = $this->psr18_client->getStreamFactory();
            if (null !== $streamFactory) {
                $stream = $streamFactory->createStream($body);
                $request = $request->withBody($stream);
            }
        }

        return $request;
    }

    public function get_http_client(): HttpClientInterface
    {
        return $this->http_client;
    }

    public static function create_response(array $data): ResponseInterface
    {
        $status = $data['status'] ?? 200;
        $headers = $data['headers'] ?? [];
        $body = is_string($data['body'] ?? null) ? $data['body'] : json_encode($data['body'] ?? '');

        return new class($status, $headers, $body) implements ResponseInterface {
            private int $statusCode;
            private array $headers;
            private string $body;
            private string $reasonPhrase = '';

            public function __construct(int $status, array $headers, string $body)
            {
                $this->statusCode = $status;
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

            public function getHeaders(): array
            {
                return $this->headers;
            }

            public function hasHeader(string $name): bool
            {
                return isset($this->headers[$name]);
            }

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
                        return $result;
                    }

                    public function getContents(): string
                    {
                        return substr($this->content, $this->position);
                    }

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

            public function withBody(StreamInterface $body): self
            {
                $clone = clone $this;
                $clone->body = $body->getContents();
                return $clone;
            }
        };
    }
}