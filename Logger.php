<?php

/**
 * Logger class for Microsoft Entra ID SSO plugin.
 *
 * Provides centralized logging using Monolog and caching using Symfony Cache.
 * Log and cache directories are stored in WordPress uploads directory.
 *
 * @package AADSSO
 */
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

// Define plugin directory if not already defined
if (!defined('AADSSO_PLUGIN_DIR')) {
    define('AADSSO_PLUGIN_DIR', dirname(__FILE__) . '/');
}

/**
 * Logger class for centralized logging and caching.
 */
class AADSSO_Logger
{
    private static ?Logger $logger = null;
    private static ?Psr16Cache $cache = null;

    public static function get_logger(): Logger
    {
        if (self::$logger === null) {
            // Use WordPress uploads directory for logs (standard writable path)
            $log_dir = null;
            if (function_exists('wp_upload_dir')) {
                $upload_dir = wp_upload_dir();
                if (empty($upload_dir['error']) && !empty($upload_dir['basedir'])) {
                    $log_dir = trailingslashit($upload_dir['basedir']) . 'aad-sso-logs';
                }
            }

            if ($log_dir === null) {
                // Fallback to plugin directory if WordPress not fully loaded or uploads misconfigured
                $log_dir = AADSSO_PLUGIN_DIR . 'logs';
            }

            if (!is_dir($log_dir)) {
                if (function_exists('wp_mkdir_p')) {
                    wp_mkdir_p($log_dir);
                } else {
                    mkdir($log_dir, 0755, true);
                }
                // Add security files to protect logs directory
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
            // Use WordPress uploads directory for cache (standard writable path)
            $cache_dir = null;
            if (function_exists('wp_upload_dir')) {
                $upload_dir = wp_upload_dir();
                if (empty($upload_dir['error']) && !empty($upload_dir['basedir'])) {
                    $cache_dir = trailingslashit($upload_dir['basedir']) . 'aad-sso-cache';
                }
            }

            if ($cache_dir === null) {
                // Fallback to plugin directory if WordPress not fully loaded or uploads misconfigured
                $cache_dir = AADSSO_PLUGIN_DIR . 'cache';
            }

            if (!is_dir($cache_dir)) {
                if (function_exists('wp_mkdir_p')) {
                    wp_mkdir_p($cache_dir);
                } else {
                    mkdir($cache_dir, 0755, true);
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