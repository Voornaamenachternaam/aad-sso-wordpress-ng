<?php

declare(strict_types=1);

define('ABSPATH', __DIR__ . '/../../../wordpress/');
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);

if (!defined('WP_CONTENT_DIR')) {
    define('WP_CONTENT_DIR', dirname(ABSPATH) . '/wp-content');
}

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

if (!function_exists('wp_verify_nonce')) {
    function wp_verify_nonce($nonce, $action = -1)
    {
        return 1;
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

$_SESSION = array();