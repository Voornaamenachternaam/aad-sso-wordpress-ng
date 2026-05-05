<?php

declare(strict_types=1);

namespace AADSSO\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Logger unit tests.
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
    public function test_logger_can_be_instantiated(): void
    {
        $this->assertTrue(class_exists('AADSSO_Logger'));
    }

    /**
     * Test get_logger returns logger instance.
     */
    public function test_get_logger_returns_logger_instance(): void
    {
        $logger = \AADSSO_Logger::get_logger();
        $this->assertNotNull($logger);
        $this->assertInstanceOf(\Psr\Log\LoggerInterface::class, $logger);
    }

    /**
     * Test get_cache returns cache instance.
     */
    public function test_get_cache_returns_cache_instance(): void
    {
        $cache = \AADSSO_Logger::get_cache();
        $this->assertNotNull($cache);
        $this->assertInstanceOf(\Psr\SimpleCache\CacheInterface::class, $cache);
    }

    /**
     * Test log_debug does not throw.
     */
    public function test_log_debug_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        \AADSSO_Logger::log_debug('Test debug message', 10);
    }

    /**
     * Test log_info does not throw.
     */
    public function test_log_info_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        \AADSSO_Logger::log_info('Test info message');
    }

    /**
     * Test log_warning does not throw.
     */
    public function test_log_warning_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        \AADSSO_Logger::log_warning('Test warning message');
    }

    /**
     * Test log_error does not throw.
     */
    public function test_log_error_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        \AADSSO_Logger::log_error('Test error message');
    }

    /**
     * Test log_exception does not throw.
     */
    public function test_log_exception_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        $exception = new \Exception('Test exception');
        \AADSSO_Logger::log_exception($exception, 'Test context');
    }

    /**
     * Test logger is singleton.
     */
    public function test_logger_is_singleton(): void
    {
        $logger1 = \AADSSO_Logger::get_logger();
        $logger2 = \AADSSO_Logger::get_logger();
        $this->assertSame($logger1, $logger2);
    }

    /**
     * Test cache is singleton.
     */
    public function test_cache_is_singleton(): void
    {
        $cache1 = \AADSSO_Logger::get_cache();
        $cache2 = \AADSSO_Logger::get_cache();
        $this->assertSame($cache1, $cache2);
    }
}
