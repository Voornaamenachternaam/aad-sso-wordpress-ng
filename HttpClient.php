<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
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
            'body' => (string) $request->getBody(),
        ]);

        $statusCode = $response->getStatusCode();
        $responseHeaders = [];
        foreach ($response->getHeaders() as $name => $values) {
            $responseHeaders[$name] = $values;
        }

        return new GuzzleResponse($statusCode, $responseHeaders, $response->getContent(false));
    }

    /**
     * @param array<string, mixed> $options
     * @return array{url: string, options: array<string, mixed>}
     */
    private function createRequestOptions(string $method, string $url, array $options): array
    {
        if (!empty($options['query'])) {
            $separator = (strpos($url, '?') !== false) ? '&' : '?';
            $url .= $separator . http_build_query(self::normalizeQueryParams($options['query']));
            unset($options['query']);
        }

        return ['url' => $url, 'options' => $options];
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
        $result = $this->createRequestOptions('GET', $url, $options);
        $request = $this->createRequest('GET', $result['url'], $result['options']);
        return $this->sendRequest($request);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function post(string $url, array $options = []): ResponseInterface
    {
        $result = $this->createRequestOptions('POST', $url, $options);
        $request = $this->createRequest('POST', $result['url'], $result['options']);
        return $this->sendRequest($request);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function createRequest(string $method, string $url, array $options = []): RequestInterface
    {
        if (!empty($options['query'])) {
            $separator = (strpos($url, '?') !== false) ? '&' : '?';
            $url .= $separator . http_build_query(self::normalizeQueryParams($options['query']));
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
                        $values[] = (string) $item;
                    }
                }
                // Only add if we have values after filtering
                if (!empty($values)) {
                    /** @var string $key */
                    $result[$key] = $values;
                }
            } elseif (\is_string($value)) {
                /** @var string $key */
                $result[$key] = $value;
            } elseif (\is_scalar($value)) {
                /** @var string $key */
                $result[$key] = (string) $value;
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
                $normalized_headers[$name] = [\is_string($values) ? $values : ''];
            }
        }

        return new GuzzleResponse($status, $normalized_headers, $body);
    }
}

/**
 * Shared trait for StreamInterface implementations in HttpClient.
 */
trait AADSSO_HttpClientStreamTrait
{
    private int $position = 0;

    abstract protected function getContent(): string;

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
        return \strlen($this->getContent());
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        return $this->position >= \strlen($this->getContent());
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
                $this->position = \strlen($this->getContent()) + $offset;
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
        $result = substr($this->getContent(), $this->position, $length);
        $this->position += \strlen($result);
        return $result;
    }

    public function getContents(): string
    {
        return substr($this->getContent(), $this->position);
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
}