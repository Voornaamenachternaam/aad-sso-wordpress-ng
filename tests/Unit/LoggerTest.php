<?php

declare(strict_types=1);

namespace AADSSO\Tests\Unit;

use PHPUnit\Framework\TestCase;

class LoggerTest extends TestCase
{
    public function test_logger_can_be_instantiated(): void
    {
        $this->assertTrue(class_exists('AADSSO_Logger'));
    }

    public function test_get_logger_returns_logger_instance(): void
    {
        $logger = AADSSO_Logger::get_logger();
        $this->assertNotNull($logger);
        $this->assertInstanceOf(\Monolog\Logger::class, $logger);
    }

    public function test_get_cache_returns_cache_instance(): void
    {
        $cache = AADSSO_Logger::get_cache();
        $this->assertNotNull($cache);
        $this->assertInstanceOf(\Symfony\Component\Cache\Psr16Cache::class, $cache);
    }

    public function test_log_debug_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        AADSSO_Logger::log_debug('Test debug message', 10);
    }

    public function test_log_info_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        AADSSO_Logger::log_info('Test info message');
    }

    public function test_log_warning_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        AADSSO_Logger::log_warning('Test warning message');
    }

    public function test_log_error_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        AADSSO_Logger::log_error('Test error message');
    }

    public function test_log_exception_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        $exception = new \Exception('Test exception');
        AADSSO_Logger::log_exception($exception, 'Test context');
    }
}