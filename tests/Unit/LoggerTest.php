<?php

declare(strict_types=1);

namespace AADSSO\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Logger unit tests.
 *
 * @internal
 */
class LoggerTest extends TestCase
{
    /**
     * Set up before each test.
     */
    protected function setUp(): void
    {
        parent::setUp();
        $reflection = new \ReflectionClass(\AADSSO_Logger::class);

        $logger_prop = $reflection->getProperty('logger');
        $logger_prop->setAccessible(true);
        $logger_prop->setValue(null, null);

        $cache_prop = $reflection->getProperty('cache');
        $cache_prop->setAccessible(true);
        $cache_prop->setValue(null, null);
    }

    /**
     * Test logger class exists.
     */
    public function testLoggerCanBeInstantiated(): void
    {
        $this->assertTrue(class_exists('AADSSO_Logger'));
    }

    /**
     * Test get_logger returns logger instance.
     */
    public function testGetLoggerReturnsLoggerInstance(): void
    {
        $logger = \AADSSO_Logger::get_logger();
        $this->assertNotNull($logger);
        $this->assertInstanceOf(\Psr\Log\LoggerInterface::class, $logger);
    }

    /**
     * Test get_cache returns cache instance.
     */
    public function testGetCacheReturnsCacheInstance(): void
    {
        $cache = \AADSSO_Logger::get_cache();
        $this->assertNotNull($cache);
        $this->assertInstanceOf(\Psr\SimpleCache\CacheInterface::class, $cache);
    }

    /**
     * Test log_debug does not throw.
     */
    public function testLogDebugDoesNotThrow(): void
    {
        $this->expectNotToPerformAssertions();
        \AADSSO_Logger::log_debug('Test debug message', 10);
    }

    /**
     * Test log_info does not throw.
     */
    public function testLogInfoDoesNotThrow(): void
    {
        $this->expectNotToPerformAssertions();
        \AADSSO_Logger::log_info('Test info message');
    }

    /**
     * Test log_warning does not throw.
     */
    public function testLogWarningDoesNotThrow(): void
    {
        $this->expectNotToPerformAssertions();
        \AADSSO_Logger::log_warning('Test warning message');
    }

    /**
     * Test log_error does not throw.
     */
    public function testLogErrorDoesNotThrow(): void
    {
        $this->expectNotToPerformAssertions();
        \AADSSO_Logger::log_error('Test error message');
    }

    /**
     * Test log_exception does not throw.
     */
    public function testLogExceptionDoesNotThrow(): void
    {
        $this->expectNotToPerformAssertions();
        $exception = new \Exception('Test exception');
        \AADSSO_Logger::log_exception($exception, 'Test context');
    }

    /**
     * Test logger is singleton.
     */
    public function testLoggerIsSingleton(): void
    {
        $logger1 = \AADSSO_Logger::get_logger();
        $logger2 = \AADSSO_Logger::get_logger();
        $this->assertSame($logger1, $logger2);
    }

    /**
     * Test cache is singleton.
     */
    public function testCacheIsSingleton(): void
    {
        $cache1 = \AADSSO_Logger::get_cache();
        $cache2 = \AADSSO_Logger::get_cache();
        $this->assertSame($cache1, $cache2);
    }

    /**
     * Test safe debug mode is enabled by default.
     */
    public function testSafeDebugModeIsEnabledByDefault(): void
    {
        $this->assertTrue(\AADSSO_Logger::get_safe_debug_mode());
    }

    /**
     * Test safe debug mode can be toggled.
     */
    public function testSafeDebugModeCanBeToggled(): void
    {
        \AADSSO_Logger::set_safe_debug_mode(false);
        $this->assertFalse(\AADSSO_Logger::get_safe_debug_mode());

        \AADSSO_Logger::set_safe_debug_mode(true);
        $this->assertTrue(\AADSSO_Logger::get_safe_debug_mode());
    }

    /**
     * Test sanitize_for_logging redacts JWT tokens.
     */
    public function testSanitizeRedactsJwtTokens(): void
    {
        \AADSSO_Logger::set_safe_debug_mode(true);

        // JWT token
        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        $result = \AADSSO_Logger::sanitize_for_logging($jwt);

        $this->assertSame('[REDACTED_SENSITIVE_DATA]', $result);
    }

    /**
     * Test sanitize_for_logging redacts Bearer tokens.
     */
    public function testSanitizeRedactsBearerTokens(): void
    {
        \AADSSO_Logger::set_safe_debug_mode(true);

        $bearer = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        $result = \AADSSO_Logger::sanitize_for_logging($bearer);

        $this->assertStringContainsString('[REDACTED_SENSITIVE_DATA]', $result);
    }

    /**
     * Test sanitize_for_logging redacts sensitive keys.
     */
    public function testSanitizeRedactsSensitiveKeys(): void
    {
        \AADSSO_Logger::set_safe_debug_mode(true);

        $data = [
            'username' => 'johndoe',
            'access_token' => 'super-secret-token-value-12345678901234567890',
            'password' => 'secretpassword',
        ];

        $result = \AADSSO_Logger::sanitize_for_logging($data);

        $this->assertSame('johndoe', $result['username']);
        $this->assertSame('[REDACTED_SENSITIVE_DATA]', $result['access_token']);
        $this->assertSame('[REDACTED_SENSITIVE_DATA]', $result['password']);
    }

    /**
     * Test sanitize_for_logging handles arrays.
     */
    public function testSanitizeHandlesArrays(): void
    {
        \AADSSO_Logger::set_safe_debug_mode(true);

        $data = [
            'users' => [
                ['name' => 'John', 'email' => 'john@example.com'],
                ['name' => 'Jane', 'email' => 'jane@example.com'],
            ],
        ];

        $result = \AADSSO_Logger::sanitize_for_logging($data);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('users', $result);
    }

    /**
     * Test sanitize_for_logging returns original when disabled.
     */
    public function testSanitizeReturnsOriginalWhenDisabled(): void
    {
        \AADSSO_Logger::set_safe_debug_mode(false);

        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        $result = \AADSSO_Logger::sanitize_for_logging($jwt);

        $this->assertSame($jwt, $result);
    }

    /**
     * Test sanitize_for_logging preserves non-sensitive strings.
     */
    public function testSanitizePreservesNonSensitiveStrings(): void
    {
        \AADSSO_Logger::set_safe_debug_mode(true);

        $data = 'This is a regular log message without sensitive data.';
        $result = \AADSSO_Logger::sanitize_for_logging($data);

        $this->assertSame($data, $result);
    }
}
