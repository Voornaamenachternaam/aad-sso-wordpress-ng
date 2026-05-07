<?php

declare(strict_types=1);

use Monolog\Handler\RotatingFileHandler;
use Monolog\{Level, Logger as MonologLogger};
use Monolog\Processor\PsrLogMessageProcessor;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;

if (!\defined('ABSPATH')) {
    exit;
}

if (!\defined('AADSSO_PLUGIN_DIR')) {
    \define('AADSSO_PLUGIN_DIR', __DIR__ . '/');
}

class Logger
{
    private static ?LoggerInterface $logger = null;

    private static ?CacheInterface $cache = null;

    public static function get_logger(): LoggerInterface
    {
        if (null === self::$logger) {
            $log_dir = null;
            if (\function_exists('wp_upload_dir')) {
                $upload_dir = wp_upload_dir();
                if (empty($upload_dir['error']) && !empty($upload_dir['basedir'])) {
                    $log_dir = trailingslashit($upload_dir['basedir']) . 'aad-sso-logs';
                }
            }

            if (null === $log_dir) {
                $log_dir = AADSSO_PLUGIN_DIR . 'logs';
            }

            if (!is_dir($log_dir)) {
                if (\function_exists('wp_mkdir_p')) {
                    wp_mkdir_p($log_dir);
                } else {
                    mkdir($log_dir, 0o755, true);
                }
                if (!file_exists($log_dir . '/.htaccess')) {
                    file_put_contents($log_dir . '/.htaccess', 'Deny from all');
                }
                if (!file_exists($log_dir . '/index.php')) {
                    file_put_contents($log_dir . '/index.php', '<?php // Silence is golden.');
                }
            }

            $handler = new RotatingFileHandler(
                $log_dir . '/aad-sso.log',
                14,
                Level::Debug
            );

            self::$logger = new MonologLogger(
                'aad-sso',
                [$handler],
                [new PsrLogMessageProcessor()]
            );
        }

        return self::$logger;
    }

    public static function get_cache(): CacheInterface
    {
        if (null === self::$cache) {
            $cache_dir = null;
            if (\function_exists('wp_upload_dir')) {
                $upload_dir = wp_upload_dir();
                if (empty($upload_dir['error']) && !empty($upload_dir['basedir'])) {
                    $cache_dir = trailingslashit($upload_dir['basedir']) . 'aad-sso-cache';
                }
            }

            if (null === $cache_dir) {
                $cache_dir = AADSSO_PLUGIN_DIR . 'cache';
            }

            if (!is_dir($cache_dir)) {
                if (\function_exists('wp_mkdir_p')) {
                    wp_mkdir_p($cache_dir);
                } else {
                    mkdir($cache_dir, 0o755, true);
                }
                if (!file_exists($cache_dir . '/.htaccess')) {
                    file_put_contents($cache_dir . '/.htaccess', 'Deny from all');
                }
                if (!file_exists($cache_dir . '/index.php')) {
                    file_put_contents($cache_dir . '/index.php', '<?php // Silence is golden.');
                }
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

        $is_enabled = filter_var($debug_enabled, \FILTER_VALIDATE_BOOLEAN);

        if (!$is_enabled || $debug_level < $level) {
            return;
        }

        self::get_logger()->debug($message);
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function log_info(string $message, array $context = []): void
    {
        $context['source'] = 'AADSSO';
        self::get_logger()->info($message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function log_warning(string $message, array $context = []): void
    {
        $context['source'] = 'AADSSO';
        self::get_logger()->warning($message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function log_error(string $message, array $context = []): void
    {
        $context['source'] = 'AADSSO';
        self::get_logger()->error($message, $context);
    }

    public static function log_exception(Throwable $exception, string $message = ''): void
    {
        $context = [
            'source' => 'AADSSO',
            'exception_class' => $exception::class,
            'exception_file' => $exception->getFile(),
            'exception_line' => $exception->getLine(),
        ];

        $log_message = $message ?: $exception->getMessage();

        self::get_logger()->error($log_message, $context);
    }
}

class_alias(Logger::class, 'AADSSO_Logger');
