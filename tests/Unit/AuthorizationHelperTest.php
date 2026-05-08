<?php

declare(strict_types=1);

namespace AADSSO\Tests\Unit;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\{ResponseInterface, StreamInterface};

/**
 * AuthorizationHelper unit tests for ID token validation.
 *
 * @internal
 */
class AuthorizationHelperTest extends TestCase
{
    /**
     * Valid client ID for testing.
     */
    private const TEST_CLIENT_ID = '11111111-2222-3333-4444-555555555555';

    /**
     * Valid issuer for testing.
     */
    private const TEST_ISSUER = 'https://login.microsoftonline.com/tenant-guid/v2.0';

    /**
     * Test RSA key pair for JWT signing.
     *
     * @var array{private_key: string, public_key: string}
     */
    private static array $rsaKeyPair;

    /**
     * Set up before all tests.
     */
    public static function setUpBeforeClass(): void
    {
        // Generate RSA key pair for testing
        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => \OPENSSL_KEYTYPE_RSA,
        ];

        $res = openssl_pkey_new($config);
        if (false === $res) {
            throw new \RuntimeException('Failed to generate RSA key pair');
        }

        openssl_pkey_export($res, $privateKey);
        $details = openssl_pkey_get_details($res);

        self::$rsaKeyPair = [
            'private_key' => $privateKey,
            'public_key' => $details['key'],
        ];
    }

    /**
     * Test that audience validation accepts token with matching aud.
     */
    public function testValidateIdTokenAcceptsMatchingAudience(): void
    {
        // We need to use reflection to test the private method
        $reflection = new \ReflectionClass(\AADSSO_AuthorizationHelper::class);
        $method = $reflection->getMethod('process_jwks_response');
        $method->setAccessible(true);

        $token = $this->generateTestToken();

        // Use reflection to set the static HTTP client to null for fresh test
        $httpClientProperty = $reflection->getProperty('http_client');
        $httpClientProperty->setAccessible(true);
        $httpClientProperty->setValue(null, null);

        $response = $this->createMockJwksResponse();

        // Call the method - should not throw
        $result = $method->invoke(null, $response, $token, 'test-nonce-123', self::TEST_CLIENT_ID);

        $this->assertIsObject($result);
        $this->assertEquals(self::TEST_CLIENT_ID, $result->aud);
    }

    /**
     * Test that audience validation rejects token with wrong aud.
     */
    public function testValidateIdTokenRejectsWrongAudience(): void
    {
        $reflection = new \ReflectionClass(\AADSSO_AuthorizationHelper::class);
        $method = $reflection->getMethod('process_jwks_response');
        $method->setAccessible(true);

        $wrongClientId = '99999999-9999-9999-9999-999999999999';
        $token = $this->generateTestToken(['aud' => $wrongClientId]);

        $httpClientProperty = $reflection->getProperty('http_client');
        $httpClientProperty->setAccessible(true);
        $httpClientProperty->setValue(null, null);

        $response = $this->createMockJwksResponse();

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage('ID token audience validation failed');

        $method->invoke(null, $response, $token, 'test-nonce-123', self::TEST_CLIENT_ID);
    }

    /**
     * Test that audience validation rejects token with missing aud.
     */
    public function testValidateIdTokenRejectsMissingAudience(): void
    {
        $reflection = new \ReflectionClass(\AADSSO_AuthorizationHelper::class);
        $method = $reflection->getMethod('process_jwks_response');
        $method->setAccessible(true);

        // Generate token without aud claim
        $now = time();
        $payload = [
            'iss' => self::TEST_ISSUER,
            'iat' => $now,
            'exp' => $now + 3600,
            'nonce' => 'test-nonce-123',
            'oid' => 'user-object-id-123',
        ];
        $token = JWT::encode($payload, self::$rsaKeyPair['private_key'], 'RS256');

        $httpClientProperty = $reflection->getProperty('http_client');
        $httpClientProperty->setAccessible(true);
        $httpClientProperty->setValue(null, null);

        $response = $this->createMockJwksResponse();

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage('ID token is missing required `aud`');

        $method->invoke(null, $response, $token, 'test-nonce-123', self::TEST_CLIENT_ID);
    }

    /**
     * Test that audience validation accepts token with aud as array containing client_id.
     */
    public function testValidateIdTokenAcceptsAudienceArray(): void
    {
        $reflection = new \ReflectionClass(\AADSSO_AuthorizationHelper::class);
        $method = $reflection->getMethod('process_jwks_response');
        $method->setAccessible(true);

        $token = $this->generateTestToken([
            'aud' => [
                'some-other-client-id',
                self::TEST_CLIENT_ID,
                'another-client-id',
            ],
        ]);

        $httpClientProperty = $reflection->getProperty('http_client');
        $httpClientProperty->setAccessible(true);
        $httpClientProperty->setValue(null, null);

        $response = $this->createMockJwksResponse();

        $result = $method->invoke(null, $response, $token, 'test-nonce-123', self::TEST_CLIENT_ID);

        $this->assertIsObject($result);
        $this->assertEquals(self::TEST_CLIENT_ID, $result->aud[1]);
    }

    /**
     * Test that audience validation rejects token with array aud not containing client_id.
     */
    public function testValidateIdTokenRejectsAudienceArrayWithoutClientId(): void
    {
        $reflection = new \ReflectionClass(\AADSSO_AuthorizationHelper::class);
        $method = $reflection->getMethod('process_jwks_response');
        $method->setAccessible(true);

        $token = $this->generateTestToken([
            'aud' => [
                'some-other-client-id',
                'another-client-id',
            ],
        ]);

        $httpClientProperty = $reflection->getProperty('http_client');
        $httpClientProperty->setAccessible(true);
        $httpClientProperty->setValue(null, null);

        $response = $this->createMockJwksResponse();

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage('ID token audience validation failed');

        $method->invoke(null, $response, $token, 'test-nonce-123', self::TEST_CLIENT_ID);
    }

    /**
     * Test that azp validation accepts token when azp matches client_id.
     */
    public function testValidateIdTokenAcceptsMatchingAzp(): void
    {
        $reflection = new \ReflectionClass(\AADSSO_AuthorizationHelper::class);
        $method = $reflection->getMethod('process_jwks_response');
        $method->setAccessible(true);

        $token = $this->generateTestToken([
            'azp' => self::TEST_CLIENT_ID,
        ]);

        $httpClientProperty = $reflection->getProperty('http_client');
        $httpClientProperty->setAccessible(true);
        $httpClientProperty->setValue(null, null);

        $response = $this->createMockJwksResponse();

        $result = $method->invoke(null, $response, $token, 'test-nonce-123', self::TEST_CLIENT_ID);

        $this->assertIsObject($result);
        $this->assertEquals(self::TEST_CLIENT_ID, $result->azp);
    }

    /**
     * Test that azp validation rejects token when azp does not match client_id.
     */
    public function testValidateIdTokenRejectsMismatchedAzp(): void
    {
        $reflection = new \ReflectionClass(\AADSSO_AuthorizationHelper::class);
        $method = $reflection->getMethod('process_jwks_response');
        $method->setAccessible(true);

        $wrongAzp = '99999999-9999-9999-9999-999999999999';
        $token = $this->generateTestToken([
            'azp' => $wrongAzp,
        ]);

        $httpClientProperty = $reflection->getProperty('http_client');
        $httpClientProperty->setAccessible(true);
        $httpClientProperty->setValue(null, null);

        $response = $this->createMockJwksResponse();

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage('ID token authorized party (azp) mismatch');

        $method->invoke(null, $response, $token, 'test-nonce-123', self::TEST_CLIENT_ID);
    }

    /**
     * Test that azp validation passes when azp is not present.
     */
    public function testValidateIdTokenPassesWhenAzpNotPresent(): void
    {
        $reflection = new \ReflectionClass(\AADSSO_AuthorizationHelper::class);
        $method = $reflection->getMethod('process_jwks_response');
        $method->setAccessible(true);

        // Token without azp claim
        $now = time();
        $payload = [
            'iss' => self::TEST_ISSUER,
            'iat' => $now,
            'exp' => $now + 3600,
            'aud' => self::TEST_CLIENT_ID,
            'nonce' => 'test-nonce-123',
            'oid' => 'user-object-id-123',
            'preferred_username' => 'testuser@example.com',
        ];
        $token = JWT::encode($payload, self::$rsaKeyPair['private_key'], 'RS256');

        $httpClientProperty = $reflection->getProperty('http_client');
        $httpClientProperty->setAccessible(true);
        $httpClientProperty->setValue(null, null);

        $response = $this->createMockJwksResponse();

        $result = $method->invoke(null, $response, $token, 'test-nonce-123', self::TEST_CLIENT_ID);

        $this->assertIsObject($result);
        $this->assertFalse(isset($result->azp));
    }

    /**
     * Test that nonce validation rejects mismatched nonce.
     */
    public function testValidateIdTokenRejectsMismatchedNonce(): void
    {
        $reflection = new \ReflectionClass(\AADSSO_AuthorizationHelper::class);
        $method = $reflection->getMethod('process_jwks_response');
        $method->setAccessible(true);

        $token = $this->generateTestToken();

        $httpClientProperty = $reflection->getProperty('http_client');
        $httpClientProperty->setAccessible(true);
        $httpClientProperty->setValue(null, null);

        $response = $this->createMockJwksResponse();

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage('Nonce mismatch');

        // Use wrong nonce
        $method->invoke(null, $response, $token, 'wrong-nonce-value', self::TEST_CLIENT_ID);
    }

    /**
     * Test that expired token is rejected.
     */
    public function testValidateIdTokenRejectsExpiredToken(): void
    {
        $reflection = new \ReflectionClass(\AADSSO_AuthorizationHelper::class);
        $method = $reflection->getMethod('process_jwks_response');
        $method->setAccessible(true);

        $token = $this->generateTestToken([
            'iat' => time() - 7200,
            'exp' => time() - 3600, // Expired 1 hour ago
        ]);

        $httpClientProperty = $reflection->getProperty('http_client');
        $httpClientProperty->setAccessible(true);
        $httpClientProperty->setValue(null, null);

        $response = $this->createMockJwksResponse();

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage('Token has expired');

        $method->invoke(null, $response, $token, 'test-nonce-123', self::TEST_CLIENT_ID);
    }

    /**
     * Generate a valid JWT token for testing.
     *
     * @param array<string, mixed> $claims Additional claims to merge
     *
     * @return string The encoded JWT token
     */
    private function generateTestToken(array $claims = []): string
    {
        $now = time();

        $payload = array_merge([
            'iss' => self::TEST_ISSUER,
            'iat' => $now,
            'exp' => $now + 3600,
            'aud' => self::TEST_CLIENT_ID,
            'nonce' => 'test-nonce-123',
            'oid' => 'user-object-id-123',
            'preferred_username' => 'testuser@example.com',
        ], $claims);

        return JWT::encode($payload, self::$rsaKeyPair['private_key'], 'RS256');
    }

    /**
     * Create a mock HTTP response with given body and status code.
     */
    private function createMockResponse(string $body, int $statusCode = 200): ResponseInterface
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($body);

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn($statusCode);
        $response->method('getBody')->willReturn($stream);

        return $response;
    }

    /**
     * Create a mock JWKS response with the test public key.
     */
    private function createMockJwksResponse(): ResponseInterface
    {
        $keyDetails = openssl_pkey_get_details(openssl_pkey_get_public(self::$rsaKeyPair['public_key']));

        $jwks = [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'kid' => 'test-key-id',
                    'alg' => 'RS256',
                    'n' => mb_rtrim(strtr(base64_encode($keyDetails['rsa']['n']), '+/', '-_'), '='),
                    'e' => mb_rtrim(strtr(base64_encode($keyDetails['rsa']['e']), '+/', '-_'), '='),
                ],
            ],
        ];

        return $this->createMockResponse(json_encode($jwks));
    }
}
