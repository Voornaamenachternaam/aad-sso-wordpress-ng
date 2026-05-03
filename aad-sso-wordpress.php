<?php

declare(strict_types=1);

/*
Plugin Name: Single Sign-on with Microsoft Entra ID
Plugin URI: http://github.com/psignoret/aad-sso-wordpress
Description: Allows you to use your organization's Microsoft Entra ID (formerly known as Azure Active Directory) user accounts to log in to WordPress. If your organization is using Office 365, your user accounts are already in Microsoft Entra ID. This plugin uses OAuth 2.0 to authenticate users, and the Microsoft Graph API to get group membership and other details.
Author: Philippe Signoret
Version: 0.9.0
Author URI: https://www.psignoret.com/
Text Domain: aad-sso-wordpress
Domain Path: /languages/
Requires PHP: 8.2
Requires at least: 6.4
Tested up to: 6.8
License: MIT
License URI: https://github.com/psignoret/aad-sso-wordpress/blob/master/LICENSE.md
*/

defined('ABSPATH') || exit;

$autoloader = __DIR__ . '/vendor/autoload.php';
if (file_exists($autoloader)) {
    require_once $autoloader;
}

define('AADSSO', 'aad-sso-wordpress');
define('AADSSO_PLUGIN_URL', plugin_dir_url(__FILE__));
define('AADSSO_PLUGIN_DIR', plugin_dir_path(__FILE__));

defined('AADSSO_DEBUG') || define('AADSSO_DEBUG', false);
defined('AADSSO_DEBUG_LEVEL') || define('AADSSO_DEBUG_LEVEL', 0);

require_once AADSSO_PLUGIN_DIR . 'Settings.php';
require_once AADSSO_PLUGIN_DIR . 'SettingsPage.php';
require_once AADSSO_PLUGIN_DIR . 'AuthorizationHelper.php';
require_once AADSSO_PLUGIN_DIR . 'GraphHelper.php';

class AADSSO
{
    private static ?AADSSO $instance = null;
    private ?AADSSO_Settings $settings = null;

    public function __construct(AADSSO_Settings $settings)
    {
        $this->settings = $settings;
        $this->setup_admin_settings();

        add_filter(
            'plugin_action_links_' . plugin_basename(__FILE__),
            [$this, 'add_settings_link']
        );

        register_activation_hook(__FILE__, [self::class, 'activate']);
        register_deactivation_hook(__FILE__, [self::class, 'deactivate']);

        if (!$this->plugin_is_configured()) {
            add_action('all_admin_notices', [$this, 'print_plugin_not_configured']);
            return;
        }

        add_action('login_init', [$this, 'register_session'], 10);
        add_filter('authenticate', [$this, 'authenticate'], 1, 3);
        add_action('login_enqueue_scripts', [$this, 'print_login_css']);
        add_action('login_form', [$this, 'print_login_link']);
        add_action('wp_logout', [$this, 'logout']);
        add_action('login_init', [$this, 'save_redirect_and_maybe_bypass_login'], 20);
        add_filter('login_redirect', [$this, 'redirect_after_login'], 20, 3);
        add_action('plugins_loaded', [$this, 'load_textdomain']);
    }

    public static function activate(): void
    {
        $stored_settings = get_option('aadsso_settings', null);
        if (null === $stored_settings) {
            update_option('aadsso_settings', AADSSO_Settings::get_defaults());
        }
    }

    public static function deactivate(): void
    {
    }

    public function load_textdomain(): void
    {
        load_plugin_textdomain(
            'aad-sso-wordpress',
            false,
            dirname(plugin_basename(__FILE__)) . '/languages/'
        );
    }

    public function plugin_is_configured(): bool
    {
        return !empty($this->settings->client_id)
            && !empty($this->settings->client_secret)
            && !empty($this->settings->redirect_uri);
    }

    public static function get_instance(AADSSO_Settings $settings): self
    {
        if (!self::$instance) {
            self::$instance = new self($settings);
        }
        return self::$instance;
    }

    public function save_redirect_and_maybe_bypass_login(): void
    {
        $auto_redirect = apply_filters(
            'aad_auto_forward_login',
            $this->settings->enable_auto_forward_to_aad
        );

        if (isset($_GET['aadsso_no_redirect'])) {
            AADSSO::debug_log('Skipping automatic redirects to Microsoft Entra ID.');
            $auto_redirect = false;
        }

        if ($this->wants_to_login()) {
            if (isset($_GET['redirect_to']) && is_string($_GET['redirect_to'])) {
                $redirect_to = wp_validate_redirect($_GET['redirect_to'], '');
                if ($redirect_to !== '') {
                    $_SESSION['aadsso_redirect_to'] = $redirect_to;
                }
            }

            if ($auto_redirect && !isset($_GET['code']) && !isset($_POST['log'])) {
                wp_redirect($this->get_login_url());
                exit;
            }
        }
    }

    public function redirect_after_login(string $redirect_to, string $requested_redirect_to, $user): string
    {
        if ($user instanceof WP_User && isset($_SESSION['aadsso_redirect_to'])) {
            $redirect_to = sanitize_url($_SESSION['aadsso_redirect_to']);
        }
        return $redirect_to;
    }

    private function wants_to_login(): bool
    {
        $wants_to_login = false;
        $action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : 'login';
        $action = isset($_GET['loggedout']) ? 'loggedout' : $action;
        if ('login' === $action) {
            $wants_to_login = true;
        }
        return $wants_to_login;
    }

    public function authenticate($user, string $username, string $password)
    {
        if (!isset($_GET['code'])) {
            return $user;
        }

        try {
            $authorization_result = AADSSO_AuthorizationHelper::get_access_token(
                sanitize_text_field(wp_unslash($_GET['code'])),
                $this->settings
            );

            if (!$authorization_result || !isset($authorization_result->id_token)) {
                return new WP_Error(
                    'aadsso_invalid_authorization',
                    __('Invalid authorization response.', 'aad-sso-wordpress')
                );
            }

            $antiforgery_id = $_SESSION['aadsso_antiforgery-id'] ?? '';
            if (empty($antiforgery_id)) {
                return new WP_Error(
                    'aadsso_missing_antiforgery',
                    __('Missing antiforgery token.', 'aad-sso-wordpress')
                );
            }

            $id_token = $authorization_result->id_token;
            $jwt = AADSSO_AuthorizationHelper::validate_id_token(
                $id_token,
                $this->settings,
                $antiforgery_id
            );

            $upn = $jwt->preferred_username ?? $jwt->email ?? '';
            if (empty($upn)) {
                return new WP_Error(
                    'aadsso_missing_upn',
                    __('Unable to determine user identity.', 'aad-sso-wordpress')
                );
            }

            $user = $this->get_wordpress_user_from_upn($upn);

            if (!$user && $this->settings->enable_auto_provisioning) {
                $user = $this->provision_wordpress_user($jwt);
            }

            if (!$user) {
                return new WP_Error(
                    'aadsso_user_not_found',
                    __('No matching WordPress user found.', 'aad-sso-wordpress')
                );
            }

            if ($this->settings->enable_aad_group_to_wp_role) {
                $user = $this->update_wp_user_roles($user, $jwt);
                if (is_wp_error($user)) {
                    return $user;
                }
            }

            $_SESSION['aadsso_signed_in_with_azuread'] = true;
            unset($_SESSION['aadsso_antiforgery-id']);

            return $user;
        } catch (Exception $e) {
            AADSSO::debug_log('Authentication error: ' . $e->getMessage());
            return new WP_Error(
                'aadsso_authentication_error',
                __('Authentication failed.', 'aad-sso-wordpress')
            );
        }
    }

    private function get_wordpress_user_from_upn(string $upn): ?WP_User
    {
        $user = null;

        switch ($this->settings->field_to_match_to_upn) {
            case 'email':
                $user = get_user_by('email', $upn);
                break;
            case 'login':
                if ($this->settings->match_on_upn_alias) {
                    $parts = explode('@', $upn);
                    $username = !empty($parts[0]) ? $parts[0] : '';
                    $user = get_user_by('login', $username);
                } else {
                    $user = get_user_by('login', $upn);
                }
                break;
        }

        return $user instanceof WP_User ? $user : null;
    }

    private function provision_wordpress_user(object $jwt): ?WP_User
    {
        $email = $jwt->email ?? $jwt->preferred_username ?? '';
        if (empty($email)) {
            return null;
        }

        $parts = explode('@', $email);
        $username = !empty($parts[0]) ? $parts[0] : '';
        $display_name = $jwt->name ?? $jwt->preferred_username ?? $username;

        if (empty($username)) {
            return null;
        }

        $base_username = $username;
        $counter = 1;
        while (username_exists($username)) {
            $username = $base_username . $counter;
            $counter++;
        }

        $user_id = wp_create_user($username, wp_generate_password(32, true), $email);

        if (is_wp_error($user_id)) {
            return null;
        }

        wp_update_user([
            'ID' => $user_id,
            'display_name' => sanitize_text_field($display_name),
            'first_name' => sanitize_text_field($jwt->given_name ?? ''),
            'last_name' => sanitize_text_field($jwt->family_name ?? ''),
        ]);

        return get_user_by('id', $user_id);
    }

    private function update_wp_user_roles(WP_User $user, object $jwt): WP_User|WP_Error
    {
        $roles_to_set = [];

        try {
            $user_id = rawurlencode($user->ID);
            $group_ids = array_keys($this->settings->aad_group_to_wp_role_map);
            $group_memberships = AADSSO_GraphHelper::user_check_member_groups($user_id, $group_ids);

            if (!empty($group_memberships->value)) {
                foreach ($this->settings->aad_group_to_wp_role_map as $aad_group => $wp_role) {
                    if (in_array($aad_group, $group_memberships->value, true)) {
                        $roles_to_set[] = $wp_role;
                    }
                }
            }
        } catch (Exception $e) {
            AADSSO::debug_log('Error checking group membership: ' . $e->getMessage());
        }

        if (!empty($roles_to_set)) {
            $user->set_role('');
            foreach ($roles_to_set as $role) {
                $user->add_role(sanitize_key($role));
            }
            AADSSO::debug_log(
                sprintf('Set roles [%s] for user [%s].', implode(', ', $roles_to_set), $user->ID),
                10
            );
        } elseif (!empty($this->settings->default_wp_role)) {
            $user->set_role(sanitize_key($this->settings->default_wp_role));
            AADSSO::debug_log(
                sprintf('Set default role [%s] for user [%s].', $this->settings->default_wp_role, $user->ID),
                10
            );
        } else {
            $error_message = sprintf(
                __('ERROR: Microsoft Entra ID user %s is not a member of any group granting a role.', 'aad-sso-wordpress'),
                esc_html($user->ID)
            );
            AADSSO::debug_log($error_message, 10);
            return new WP_Error('user_not_member_of_required_group', $error_message);
        }

        return $user;
    }

    public function add_settings_link(array $links): array
    {
        $links[] = '<a href="' . esc_url(admin_url('options-general.php?page=aadsso_settings')) . '">'
            . esc_html__('Settings', 'aad-sso-wordpress') . '</a>';
        return $links;
    }

    public function get_login_url(): string
    {
        $antiforgery_id = aad_sso_create_uuid();
        $_SESSION['aadsso_antiforgery-id'] = $antiforgery_id;
        return AADSSO_AuthorizationHelper::get_authorization_url($this->settings, $antiforgery_id);
    }

    public function get_logout_url(): string
    {
        $logout_redirect_uri = $this->settings->logout_redirect_uri;
        if (empty($logout_redirect_uri)) {
            $logout_redirect_uri = AADSSO_Settings::get_defaults('logout_redirect_uri');
        }

        return $this->settings->end_session_endpoint
            . '?' . http_build_query(['post_logout_redirect_uri' => $logout_redirect_uri]);
    }

    public function register_session(): void
    {
        if (!session_id()) {
            session_start();
        }
    }

    public function clear_session(): void
    {
        if (session_id()) {
            $_SESSION = [];
            session_destroy();
        }
    }

    public function logout(): void
    {
        $signed_in_with_azuread = isset($_SESSION['aadsso_signed_in_with_azuread'])
            && true === $_SESSION['aadsso_signed_in_with_azuread'];
        $this->clear_session();

        if ($signed_in_with_azuread && $this->settings->enable_full_logout) {
            wp_redirect($this->get_logout_url());
            exit;
        }
    }

    public function setup_admin_settings(): void
    {
        if (is_admin()) {
            new AADSSO_Settings_Page();
        }
    }

    public function print_plugin_not_configured(): void
    {
        echo '<div id="message" class="error"><p>'
            . esc_html__('Single Sign-on with Microsoft Entra ID required settings are not defined. ', 'aad-sso-wordpress')
            . esc_html__('Update them under Settings > Microsoft Entra ID.', 'aad-sso-wordpress')
            . '</p></div>';
    }

    public function print_debug(): void
    {
        echo '<p>SESSION</p><pre>' . esc_html(var_export($_SESSION, true)) . '</pre>';
        echo '<p>GET</pre><pre>' . esc_html(var_export($_GET, true)) . '</pre>';
        echo '<p>Database settings</p><pre>' . esc_html(var_export(get_option('aadsso_settings'), true)) . '</pre>';
        echo '<p>Plugin settings</p><pre>' . esc_html(var_export($this->settings, true)) . '</pre>';
    }

    public function print_login_css(): void
    {
        wp_enqueue_style(AADSSO, AADSSO_PLUGIN_URL . 'login.css');
    }

    public function print_login_link(): void
    {
        $org_name = !empty($this->settings->org_display_name)
            ? esc_html($this->settings->org_display_name)
            : 'Organization';

        echo '<p class="aadsso-login-form-text">';
        echo '<a href="' . esc_url($this->get_login_url()) . '">';
        echo esc_html(sprintf(
            __('Sign in with your %s account', 'aad-sso-wordpress'),
            $org_name
        ));
        echo '</a><br />';
        echo '<a class="dim" href="' . esc_url($this->get_logout_url()) . '">';
        echo esc_html__('Sign out', 'aad-sso-wordpress');
        echo '</a></p>';
    }

    public static function debug_log($message, int $level = 0): void
    {
        do_action('aad_sso_debug_log', $message);

        $debug_enabled = apply_filters('aad_sso_debug', AADSSO_DEBUG);
        $debug_level = apply_filters('aad_sso_debug_level', AADSSO_DEBUG_LEVEL);

        if (true === $debug_enabled && $debug_level >= $level) {
            if (false === strpos((string) $message, "\n")) {
                error_log('AADSSO: ' . $message);
            } else {
                $lines = explode("\n", str_replace("\r\n", "\n", (string) $message));
                foreach ($lines as $line) {
                    AADSSO::debug_log($line, $level);
                }
            }
        }
    }

    public static function debug_print_backtrace(int $level = 10): void
    {
        ob_start();
        debug_print_backtrace();
        $trace = ob_get_contents();
        ob_end_clean();
        self::debug_log($trace, $level);
    }
}

if (!function_exists('aad_sso_create_uuid')) {
    function aad_sso_create_uuid(): string
    {
        $random_bytes = random_bytes(16);

        $random_bytes[6] = chr(ord($random_bytes[6]) & 0x0f | 0x40);
        $random_bytes[8] = chr(ord($random_bytes[8]) & 0x3f | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($random_bytes), 4));
    }
}

$aadsso_settings_instance = AADSSO_Settings::init();
$aadsso = AADSSO::get_instance($aadsso_settings_instance);