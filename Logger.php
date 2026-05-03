<?php

declare(strict_types=1);

use Monolog\Handler\RotatingFileHandler;
use Monolog\Level;
use Monolog\Logger;
use Monolog\Processor\PsrLogMessageProcessor;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;

if (!defined('ABSPATH')) {
    exit;
}

class AADSSO_Logger
{
    private static ?Logger $logger = null;
    private static ?Psr16Cache $cache = null;

    public static function get_logger(): Logger
    {
        if (self::$logger === null) {
            $log_dir = AADSSO_PLUGIN_DIR . 'logs';
            if (!is_dir($log_dir)) {
                wp_mkdir_p($log_dir);
                file_put_contents($log_dir . '/.htaccess', 'Deny from all');
                file_put_contents($log_dir . '/index.php', '<?php // Silence is golden.');
            }

            $handler = new RotatingFileHandler(
                $log_dir . '/aad-sso.log',
                14,
                Level::Debug
            );

            self::$logger = new Logger(
                'aad-sso',
                [$handler],
                [new PsrLogMessageProcessor()]
            );
        }

        return self::$logger;
    }

    public static function get_cache(): Psr16Cache
    {
        if (self::$cache === null) {
            $cache_dir = AADSSO_PLUGIN_DIR . 'cache';
            if (!is_dir($cache_dir)) {
                wp_mkdir_p($cache_dir);
            }

            $filesystem_adapter = new FilesystemAdapter('', 0, $cache_dir);
            self::$cache = new Psr16Cache($filesystem_adapter);
        }

        return self::$cache;
    }

    public static function log_debug(string $message, int $level = 0): void
    {
        $debug_enabled = apply_filters('aadsso_debug', AADSSO_DEBUG);
        $debug_level = apply_filters('aadsso_debug_level', AADSSO_DEBUG_LEVEL);

        if (true !== $debug_enabled || $debug_level < $level) {
            return;
        }

        $context = array(
            'level' => $level,
            'source' => 'AADSSO',
        );

        self::get_logger()->debug($message, $context);
    }

    public static function log_info(string $message, array $context = array()): void
    {
        $context['source'] = 'AADSSO';
        self::get_logger()->info($message, $context);
    }

    public static function log_warning(string $message, array $context = array()): void
    {
        $context['source'] = 'AADSSO';
        self::get_logger()->warning($message, $context);
    }

    public static function log_error(string $message, array $context = array()): void
    {
        $context['source'] = 'AADSSO';
        self::get_logger()->error($message, $context);
    }

    public static function log_exception(\Throwable $exception, string $message = ''): void
    {
        $context = array(
            'source' => 'AADSSO',
            'exception_class' => get_class($exception),
            'exception_file' => $exception->getFile(),
            'exception_line' => $exception->getLine(),
        );

        if (!empty($message)) {
            $context['message'] = $message;
        }

        self::get_logger()->error(
            $message ?: $exception->getMessage(),
            $context
        );
    }
}