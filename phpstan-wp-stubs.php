<?php

/**
 * WordPress Core Stub File for PHPStan
 * This file provides type hints for WordPress functions and classes.
 * @see https://github.com/szepeviktor/phpstan-wordpress
 */

// WordPress global functions
if (!function_exists('add_filter')) {
    function add_filter(string $hook_name, callable $callback, int $priority = 10, int $accepted_args = 1): bool {}
}

if (!function_exists('add_action')) {
    function add_action(string $hook_name, callable $callback, int $priority = 10, int $accepted_args = 1): bool {}
}

if (!function_exists('apply_filters')) {
    function apply_filters(string $hook_name, mixed $value, mixed ...$args): mixed {}
}

if (!function_exists('do_action')) {
    function do_action(string $hook_name, mixed $arg = ''): void {}
}

if (!function_exists('plugin_basename')) {
    function plugin_basename(string $file): string {}
}

if (!function_exists('plugin_dir_url')) {
    function plugin_dir_url(string $file): string {}
}

if (!function_exists('plugin_dir_path')) {
    function plugin_dir_path(string $file): string {}
}

if (!function_exists('admin_url')) {
    function admin_url(string $path = '', string $scheme = 'admin'): string {}
}

if (!function_exists('wp_login_url')) {
    function wp_login_url(string $redirect = '', bool $force_reauth = false): string {}
}

if (!function_exists('wp_redirect')) {
    function wp_redirect(string $location, int $status = 302): bool {}
}

if (!function_exists('wp_verify_nonce')) {
    function wp_verify_nonce(?string $nonce, string $action = -1): int|false {}
}

if (!function_exists('wp_nonce_url')) {
    function wp_nonce_url(string $url, string $action = -1): string {}
}

if (!function_exists('wp_remote_get')) {
    function wp_remote_get(string $url, array $args = array()): array|\WP_Error {}
}

if (!function_exists('wp_remote_post')) {
    function wp_remote_post(string $url, array $args = array()): array|\WP_Error {}
}

if (!function_exists('wp_remote_retrieve_body')) {
    function wp_remote_retrieve_body(array|\WP_Error $response): string {}
}

if (!function_exists('wp_remote_retrieve_headers')) {
    function wp_remote_retrieve_headers(array|\WP_Error $response): \WP_HttpHeaders|array {}
}

if (!function_exists('wp_json_encode')) {
    function wp_json_encode(mixed $data, int $options = 0, int $depth = 512): string|false {}
}

if (!function_exists('get_option')) {
    function get_option(string $option, mixed $default = false): mixed {}
}

if (!function_exists('update_option')) {
    function update_option(string $option, mixed $value, bool $autoload = null): bool {}
}

if (!function_exists('delete_option')) {
    function delete_option(string $option): bool {}
}

if (!function_exists('get_transient')) {
    function get_transient(string $transient): mixed {}
}

if (!function_exists('set_transient')) {
    function set_transient(string $transient, mixed $value, int $expiration = 0): bool {}
}

if (!function_exists('delete_transient')) {
    function delete_transient(string $transient): bool {}
}

if (!function_exists('get_user_by')) {
    function get_user_by(string $field, int|string $value): \WP_User|false {}
}

if (!function_exists('wp_insert_user')) {
    function wp_insert_user(array|object $userdata): int|\WP_Error {}
}

if (!function_exists('get_current_screen')) {
    function get_current_screen(): ?\WP_Screen {}
}

if (!function_exists('add_options_page')) {
    function add_options_page(string $page_title, string $menu_title, string $capability, string $menu_slug, callable $function = ''): string|false {}
}

if (!function_exists('register_setting')) {
    function register_setting(string $option_group, string $option_name, array $args = array()): void {}
}

if (!function_exists('add_settings_section')) {
    function add_settings_section(string $id, string $title, callable $callback, string $page): void {}
}

if (!function_exists('add_settings_field')) {
    function add_settings_field(string $id, string $title, callable $callback, string $page, string $section = 'default', array $args = array()): void {}
}

if (!function_exists('settings_fields')) {
    function settings_fields(string $option_group): void {}
}

if (!function_exists('do_settings_sections')) {
    function do_settings_sections(string $page): void {}
}

if (!function_exists('submit_button')) {
    function submit_button(string $text = '', string $type = 'primary', string $name = 'submit', bool $wrap = true, array|string $other_attributes = ''): void {}
}

if (!function_exists('load_plugin_textdomain')) {
    function load_plugin_textdomain(string $domain, bool $deprecated = false, string $plugin_rel_path = false): bool {}
}

if (!function_exists('register_activation_hook')) {
    function register_activation_hook(string $file, callable $function): void {}
}

if (!function_exists('register_deactivation_hook')) {
    function register_deactivation_hook(string $file, callable $function): void {}
}

if (!function_exists('wp_enqueue_style')) {
    function wp_enqueue_style(string $handle, string $src = '', array $deps = array(), string|bool|null $ver = false, string $media = 'all'): void {}
}

if (!function_exists('wp_enqueue_script')) {
    function wp_enqueue_script(string $handle, string $src = '', array $deps = array(), string|bool|null $ver = false, bool $in_footer = false): void {}
}

if (!function_exists('get_bloginfo')) {
    function get_bloginfo(string $show = '', string $filter = 'raw'): string {}
}

if (!function_exists('trailingslashit')) {
    function trailingslashit(string $string): string {}
}

if (!function_exists('remove_query_arg')) {
    function remove_query_arg(string|array $key, bool $uri = false): string {}
}

if (!function_exists('get_editable_roles')) {
    function get_editable_roles(): array {}
}

if (!function_exists('is_admin')) {
    function is_admin(): bool {}
}

if (!function_exists('is_wp_error')) {
    function is_wp_error($thing): bool {}
}

if (!function_exists('is_a')) {
    function is_a(object $object, string $class_name, bool $allow_string = false): bool {}
}

if (!function_exists('esc_html')) {
    function esc_html(string $text): string {}
}

if (!function_exists('esc_html__')) {
    function esc_html__(string $text, string $domain = 'default'): string {}
}

if (!function_exists('esc_attr')) {
    function esc_attr(string $text): string {}
}

if (!function_exists('esc_url')) {
    function esc_url(?string $url, array<string, string> $protocols = array(), string $context = 'display'): ?string {}
}

if (!function_exists('esc_html__')) {
    function esc_html__(string $text, string $domain = 'default'): string {}
}

if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field(string $str): string {}
}

if (!function_exists('sanitize_url')) {
    function sanitize_url(string $url, array<string, string> $protocols = array()): string {}
}

// WordPress Classes
class WP_User {
    public int $ID;
    public string $user_login;
    public string $user_pass;
    public string $user_nicename;
    public string $user_email;
    public string $user_url;
    public string $user_registered;
    public string $user_activation_key;
    public int $user_status;
    public string $display_name;
    public array $roles = array();
    public array $caps = array();
    public array $cap_key = '';
    public array $filter = array();
    
    public function set_role(string $role): void {}
    public function add_role(string $role): void {}
    public function remove_role(string $role): void {}
    public function exists(): bool {}
}

class WP_Error {
    public function __construct(string $code = '', string $message = '', array $data = array()) {}
    public function get_error_code(): string {}
    public function get_error_message(string $code = ''): string {}
    public function get_error_data(string $code = ''): mixed {}
    public function add(string $code, string $message, array $data = array()): void {}
}

class WP_Screen {
    public string $id;
    public string $base;
    public string $parent_base;
    public string $parent_file;
    public string $action;
    public string $post_type;
    public string $taxonomy;
}

class WP_Http_Headers {
    public function offsetExists(string $key): bool {}
    public function offsetGet(string $key): mixed {}
    public function offsetSet(string $key, mixed $value): void {}
    public function offsetUnset(string $key): void {}
}

class WP_Rest_Response {
    public function __construct(mixed $data = null, int $status = 200, array $headers = array()) {}
}