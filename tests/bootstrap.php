<?php

declare(strict_types=1);

// Allow ABSPATH to be overridden via environment variable (for CI/standalone setups)
// This is the standard WordPress convention: check env first, then use default
if (defined('ABSPATH')) {
    // Already defined (e.g., by WordPress test suite or parent configuration)
} elseif (getenv('ABSPATH') !== false) {
    define('ABSPATH', rtrim(getenv('ABSPATH'), '/') . '/');
} else {
    // Fallback for plugin installed in standard wp-content/plugins location
    $default_path = __DIR__ . '/../../../wordpress/';
    // Only use if it exists, otherwise use plugin dir as safe fallback
    define('ABSPATH', is_dir($default_path) ? $default_path : __DIR__ . '/../');
}

// Bridge environment variables to PHP constants (for PHPUnit test configuration)
// Note: getenv() returns strings, so we convert to appropriate types
if (!defined('AADSSO_DEBUG')) {
    $env_debug = getenv('AADSSO_DEBUG');
    define('AADSSO_DEBUG', $env_debug !== false && filter_var($env_debug, FILTER_VALIDATE_BOOLEAN));
}
if (!defined('AADSSO_DEBUG_LEVEL')) {
    $env_level = getenv('AADSSO_DEBUG_LEVEL');
    define('AADSSO_DEBUG_LEVEL', $env_level !== false ? (int) $env_level : 0);
}

define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
define('AADSSO_PLUGIN_DIR', __DIR__ . '/../');

if (!defined('WP_CONTENT_DIR')) {
    define('WP_CONTENT_DIR', dirname(ABSPATH) . '/wp-content');
}

// Load the Logger class for tests
require_once AADSSO_PLUGIN_DIR . 'Logger.php';

// Load the Settings class for tests
require_once AADSSO_PLUGIN_DIR . 'Settings.php';

if (!function_exists('get_bloginfo')) {
    function get_bloginfo($show = '', $filter = 'raw')
    {
        return 'Test Site';
    }
}

if (!function_exists('wp_login_url')) {
    function wp_login_url($redirect = '', $force_reauth = false)
    {
        return 'https://example.com/wp-login.php';
    }
}

if (!function_exists('wp_mkdir_p')) {
    function wp_mkdir_p($target)
    {
        if (is_dir($target)) {
            return true;
        }
        if (is_file($target)) {
            return false;
        }
        return mkdir($target, 0755, true);
    }
}

if (!function_exists('plugin_dir_url')) {
    function plugin_dir_url($file)
    {
        return 'https://example.com/wp-content/plugins/aad-sso-wordpress/';
    }
}

if (!function_exists('plugin_dir_path')) {
    function plugin_dir_path($file)
    {
        return dirname($file) . '/';
    }
}

if (!function_exists('plugin_basename')) {
    function plugin_basename($file)
    {
        return 'aad-sso-wordpress/aad-sso-wordpress.php';
    }
}

if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($str)
    {
        return trim(strip_tags($str));
    }
}

if (!function_exists('sanitize_email')) {
    function sanitize_email($email)
    {
        return filter_var($email, FILTER_SANITIZE_EMAIL);
    }
}

if (!function_exists('sanitize_user')) {
    function sanitize_user($username, $strict = false)
    {
        return preg_replace('|[^a-z0-9 _.\-@]|i', '', $username);
    }
}

if (!function_exists('esc_url_raw')) {
    function esc_url_raw($url, $protocols = null)
    {
        return filter_var($url, FILTER_SANITIZE_URL);
    }
}

if (!function_exists('esc_html')) {
    function esc_html($text, $domain = 'default')
    {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_attr')) {
    function esc_attr($text)
    {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_url')) {
    function esc_url($url, $protocols = null, $_context = 'display')
    {
        return filter_var($url, FILTER_SANITIZE_URL);
    }
}

if (!function_exists('wp_safe_redirect')) {
    function wp_safe_redirect($location, $status = 302)
    {
        header('Location: ' . $location, true, $status);
        exit;
    }
}

if (!function_exists('admin_url')) {
    function admin_url($path = '', $scheme = 'admin')
    {
        return 'https://example.com/wp-admin/' . ltrim($path, '/');
    }
}

if (!function_exists('is_admin')) {
    function is_admin()
    {
        return false;
    }
}

if (!function_exists('load_plugin_textdomain')) {
    function load_plugin_textdomain($domain, $deprecated = false, $plugin_rel_path = false)
    {
        return true;
    }
}

if (!function_exists('add_filter')) {
    function add_filter($tag, $function_to_add, $priority = 10, $accepted_args = 1)
    {
        return true;
    }
}

if (!function_exists('add_action')) {
    function add_action($tag, $function_to_add, $priority = 10, $accepted_args = 1)
    {
        return true;
    }
}

if (!function_exists('apply_filters')) {
    function apply_filters($tag, $value)
    {
        return $value;
    }
}

if (!function_exists('do_action')) {
    function do_action($tag, ...$args)
    {
        return null;
    }
}

if (!function_exists('register_activation_hook')) {
    function register_activation_hook($file, $function)
    {
        return null;
    }
}

if (!function_exists('register_deactivation_hook')) {
    function register_deactivation_hook($file, $function)
    {
        return null;
    }
}

if (!function_exists('get_option')) {
    function get_option($option, $default = false)
    {
        return $default;
    }
}

if (!function_exists('update_option')) {
    function update_option($option, $value)
    {
        return true;
    }
}

if (!function_exists('delete_option')) {
    function delete_option($option)
    {
        return true;
    }
}

if (!function_exists('get_transient')) {
    function get_transient($transient)
    {
        return false;
    }
}

if (!function_exists('set_transient')) {
    function set_transient($transient, $value, $expiration = 0)
    {
        return true;
    }
}

if (!function_exists('delete_transient')) {
    function delete_transient($transient)
    {
        return true;
    }
}

if (!function_exists('wp_remote_get')) {
    function wp_remote_get($url, $args = array())
    {
        return array('body' => '{}');
    }
}

if (!function_exists('wp_remote_post')) {
    function wp_remote_post($url, $args = array())
    {
        return array('body' => '{"access_token": "test"}');
    }
}

if (!function_exists('wp_remote_retrieve_body')) {
    function wp_remote_retrieve_body($response)
    {
        if (is_array($response) && isset($response['body'])) {
            return $response['body'];
        }
        return '';
    }
}

if (!function_exists('wp_remote_retrieve_headers')) {
    function wp_remote_retrieve_headers($response)
    {
        return array();
    }
}

if (!function_exists('is_wp_error')) {
    function is_wp_error($thing)
    {
        return ($thing instanceof WP_Error);
    }
}

if (!class_exists('WP_Error')) {
    class WP_Error
    {
        public $errors = array();
        public $error_data = array();

        public function __construct($code = '', $message = '', $data = '')
        {
            if (empty($code)) {
                return;
            }
            $this->errors[$code] = array($message);
            if (!empty($data)) {
                $this->error_data[$code] = $data;
            }
        }

        public function get_error_code()
        {
            $codes = $this->get_error_codes();
            if (empty($codes)) {
                return '';
            }
            return $codes[0];
        }

        public function get_error_message($code = '')
        {
            if (empty($code)) {
                $code = $this->get_error_code();
            }
            $messages = $this->get_error_messages($code);
            if (empty($messages)) {
                return '';
            }
            return $messages[0];
        }

        public function get_error_codes()
        {
            if (empty($this->errors)) {
                return array();
            }
            return array_keys($this->errors);
        }

        public function get_error_messages($code = '')
        {
            if (empty($code)) {
                $all_messages = array();
                foreach ((array) $this->errors as $code => $messages) {
                    $all_messages = array_merge($all_messages, $messages);
                }
                return $all_messages;
            }
            if (isset($this->errors[$code])) {
                return $this->errors[$code];
            }
            return array();
        }
    }
}

if (!class_exists('WP_User')) {
    class WP_User
    {
        public $ID = 0;
        public $user_email = '';
        public $user_login = '';

        public function __construct($id = 0)
        {
            $this->ID = (int) $id;
        }

        public function add_role($role)
        {
        }

        public function set_role($role)
        {
        }

        public function has_cap($cap)
        {
            return true;
        }
    }
}

if (!function_exists('wp_roles')) {
    function wp_roles()
    {
        global $wp_roles;
        if (!isset($wp_roles)) {
            $wp_roles = new stdClass();
            $wp_roles->roles = array(
                'administrator' => array('name' => 'Administrator'),
                'editor' => array('name' => 'Editor'),
                'author' => array('name' => 'Author'),
                'contributor' => array('name' => 'Contributor'),
                'subscriber' => array('name' => 'Subscriber'),
            );
        }
        return $wp_roles;
    }
}

if (!function_exists('wp_json_encode')) {
    function wp_json_encode($data, $options = 0, $depth = 512)
    {
        return json_encode($data, $options, $depth);
    }
}

if (!function_exists('wp_unslash')) {
    function wp_unslash($value)
    {
        return stripslashes($value);
    }
}

if (!function_exists('trailingslashit')) {
    function trailingslashit($string)
    {
        return rtrim($string, '/') . '/';
    }
}

if (!function_exists('wp_upload_dir')) {
    function wp_upload_dir($time = null, $dir = null, $single = false)
    {
        $base = '/tmp/wordpress-test-uploads';
        return array(
            'path' => $base,
            'url' => 'https://example.com/wp-content/uploads',
            'subdir' => '',
            'basedir' => $base,
            'baseurl' => 'https://example.com/wp-content/uploads',
            'error' => false,
        );
    }
}

if (!function_exists('add_query_arg')) {
    /**
     * Stub for WordPress add_query_arg().
     * Supports: add_query_arg($key, $value), add_query_arg($key, $value, $uri), add_query_arg($array), add_query_arg($array, $uri)
     */
    function add_query_arg(...$args)
    {
        if (empty($args)) {
            return '';
        }

        // Determine if first arg is an array (key=>value pairs) or a key name
        if (is_array($args[0])) {
            $query = $args[0];
            $uri = $args[1] ?? ($_SERVER['REQUEST_URI'] ?? '');
        } else {
            $key = $args[0];
            $value = $args[1] ?? '';
            $uri = $args[2] ?? ($_SERVER['REQUEST_URI'] ?? '');
            $query = array($key => $value);
        }

        $uri = strtok((string) $uri, '?');
        if (!empty($query)) {
            $uri .= '?' . http_build_query($query);
        }
        return $uri;
    }
}

if (!function_exists('remove_query_arg')) {
    /**
     * Stub for WordPress remove_query_arg().
     * Supports: remove_query_arg($key), remove_query_arg($key, $url)
     */
    function remove_query_arg($key, $url = '')
    {
        $url = $url ?: ($_SERVER['REQUEST_URI'] ?? '');
        $url = strtok((string) $url, '?');

        if (is_array($key)) {
            foreach ($key as $k) {
                $url = preg_replace('/([?&])' . preg_quote((string) $k, '/') . '=[^&]*&?/', '$1', $url);
            }
        } else {
            $url = preg_replace('/([?&])' . preg_quote((string) $key, '/') . '=[^&]*&?/', '$1', $url);
        }

        // Clean up trailing ? or & that may remain
        $url = rtrim($url, '?');
        $url = rtrim($url, '&');

        return $url;
    }
}

if (!function_exists('wp_die')) {
    function wp_die($message = '', $title = '', $args = array())
    {
        throw new \Exception($message);
    }
}

if (!function_exists('checked')) {
    function checked($checked, $current = true, $display = true)
    {
        return $checked === $current ? ($display ? ' checked="checked"' : ' checked') : '';
    }
}

if (!function_exists('selected')) {
    function selected($selected, $current = true, $display = true)
    {
        return $selected === $current ? ($display ? ' selected="selected"' : ' selected') : '';
    }
}

if (!function_exists('wp_kses_post')) {
    function wp_kses_post($string)
    {
        return $string;
    }
}

if (!function_exists('get_current_screen')) {
    function get_current_screen()
    {
        return null;
    }
}

if (!function_exists('wp_verify_nonce')) {
    function wp_verify_nonce($nonce, $action = -1)
    {
        return 1;
    }
}

if (!function_exists('check_admin_referer')) {
    function check_admin_referer($action = -1, $query_arg = '_wpnonce')
    {
        return true;
    }
}

if (!function_exists('sanitize_url')) {
    function sanitize_url($url, $protocols = null)
    {
        return filter_var($url, FILTER_SANITIZE_URL);
    }
}

if (!function_exists('current_user_can')) {
    function current_user_can($capability, ...$args)
    {
        return true;
    }
}

if (!function_exists('wp_create_nonce')) {
    function wp_create_nonce($action = -1)
    {
        return 'test_nonce';
    }
}

if (!function_exists('sanitize_textarea_field')) {
    function sanitize_textarea_field($str)
    {
        return sanitize_text_field($str);
    }
}

if (!function_exists('wp_strip_all_tags')) {
    function wp_strip_all_tags($str)
    {
        return strip_tags($str);
    }
}

// Mock PSR-18 HTTP client classes for testing
if (!class_exists('Psr\Http\Client\ClientInterface')) {
    interface ClientInterface
    {
        public function sendRequest(\Psr\Http\Message\RequestInterface $request): \Psr\Http\Message\ResponseInterface;
    }
}

if (!class_exists('Psr\Http\Message\RequestInterface')) {
    interface RequestInterface extends \Psr\Http\Message\MessageInterface
    {
        public function getRequestTarget(): string;
        public function withRequestTarget(string $requestTarget): self;
        public function getMethod(): string;
        public function withMethod(string $method): self;
        public function getUri(): \Psr\Http\Message\UriInterface;
        public function withUri(\Psr\Http\Message\UriInterface $uri, bool $preserveHost = false): self;
    }
}

if (!class_exists('Psr\Http\Message\ResponseInterface')) {
    interface ResponseInterface extends \Psr\Http\Message\MessageInterface
    {
        public function getStatusCode(): int;
        public function withStatus(int $code, string $reasonPhrase = ''): self;
        public function getReasonPhrase(): string;
    }
}

if (!class_exists('Psr\Http\Message\MessageInterface')) {
    interface MessageInterface
    {
        public function getProtocolVersion(): string;
        public function withProtocolVersion(string $version): self;
        public function getHeaders(): array;
        public function hasHeader(string $name): bool;
        public function getHeader(string $name): array;
        public function getHeaderLine(string $name): string;
        public function withHeader(string $name, $value): self;
        public function withAddedHeader(string $name, $value): self;
        public function withoutHeader(string $name): self;
        public function getBody(): \Psr\Http\Message\StreamInterface;
        public function withBody(\Psr\Http\Message\StreamInterface $body): self;
    }
}

if (!class_exists('Psr\Http\Message\UriInterface')) {
    interface UriInterface
    {
        public function getScheme(): string;
        public function withScheme(string $scheme): self;
        public function getAuthority(): string;
        public function getUserInfo(): string;
        public function withUserInfo(string $user, ?string $password = null): self;
        public function getHost(): string;
        public function withHost(string $host): self;
        public function getPort(): ?int;
        public function withPort(?int $port): self;
        public function getPath(): string;
        public function withPath(string $path): self;
        public function getQuery(): string;
        public function withQuery(string $query): self;
        public function getFragment(): string;
        public function withFragment(string $fragment): self;
        public function __toString(): string;
    }
}

if (!class_exists('Psr\Http\Message\StreamInterface')) {
    interface StreamInterface
    {
        public function __toString(): string;
        public function close(): void;
        public function detach();
        public function getSize(): ?int;
        public function tell(): int;
        public function eof(): bool;
        public function isSeekable(): bool;
        public function seek(int $offset, int $whence = SEEK_SET): void;
        public function rewind(): void;
        public function isWritable(): bool;
        public function write(string $string): int;
        public function isReadable(): bool;
        public function read(int $length): string;
        public function getContents(): string;
        public function getMetadata(?string $key = null);
    }
}

// Mock AADSSO_HttpClient for tests
if (!class_exists('AADSSO_HttpClient')) {
    class AADSSO_HttpClient implements \Psr\Http\Client\ClientInterface
    {
        private static $instance = null;

        public static function get_instance(): self
        {
            if (self::$instance === null) {
                self::$instance = new self();
            }
            return self::$instance;
        }

        public function sendRequest(\Psr\Http\Message\RequestInterface $request): \Psr\Http\Message\ResponseInterface
        {
            return $this->createMockResponse();
        }

        public function get(string $url, array $options = array()): \Psr\Http\Message\ResponseInterface
        {
            return $this->createMockResponse();
        }

        public function post(string $url, array $options = array()): \Psr\Http\Message\ResponseInterface
        {
            return $this->createMockResponse();
        }

        private function createMockResponse(): \Psr\Http\Message\ResponseInterface
        {
            return new class implements \Psr\Http\Message\ResponseInterface {
                private $statusCode = 200;
                private $headers = array('Content-Type' => array('application/json'));
                private $body;

                public function __construct()
                {
                    $this->body = new class {
                        public function getContents(): string
                        {
                            return '{"access_token":"test","token_type":"Bearer"}';
                        }
                    };
                }

                public function getStatusCode(): int
                {
                    return $this->statusCode;
                }

                public function withStatus(int $code, string $reasonPhrase = ''): self
                {
                    $clone = clone $this;
                    $clone->statusCode = $code;
                    return $clone;
                }

                public function getReasonPhrase(): string
                {
                    return 'OK';
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
                    return $this->headers[$name] ?? array();
                }

                public function getHeaderLine(string $name): string
                {
                    return implode(', ', $this->getHeader($name));
                }

                public function withHeader(string $name, $value): self
                {
                    $clone = clone $this;
                    $clone->headers[$name] = (array) $value;
                    return $clone;
                }

                public function withAddedHeader(string $name, $value): self
                {
                    return $this->withHeader($name, $value);
                }

                public function withoutHeader(string $name): self
                {
                    $clone = clone $this;
                    unset($clone->headers[$name]);
                    return $clone;
                }

                public function getBody(): \Psr\Http\Message\StreamInterface
                {
                    return $this->body;
                }

                public function withBody(\Psr\Http\Message\StreamInterface $body): self
                {
                    $clone = clone $this;
                    $clone->body = $body;
                    return $clone;
                }
            };
        }
    }
}

$_SESSION = array();