<?php

declare(strict_types=1);

/*
Plugin Name: Single Sign-on with Microsoft Entra ID
Plugin URI: https://github.com/psignoret/aad-sso-wordpress
Description: Allows you to use your organization's Microsoft Entra ID (formerly known as Azure Active Directory) user accounts to log in to WordPress. If your organization is using Office 365, your user accounts are already in Microsoft Entra ID. This plugin uses OAuth 2.0 to authenticate users, and the Microsoft Graph API to get group membership and other details.
Author: Philippe Signoret
Version: 0.8.0
Author URI: https://www.psignoret.com/
Text Domain: aad-sso-wordpress
Domain Path: /languages/
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 8.1
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

require_once AADSSO_PLUGIN_DIR . '/Settings.php';
require_once AADSSO_PLUGIN_DIR . '/SettingsPage.php';
require_once AADSSO_PLUGIN_DIR . '/AuthorizationHelper.php';
require_once AADSSO_PLUGIN_DIR . '/GraphHelper.php';

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
            array($this, 'add_settings_link')
        );

        register_activation_hook(__FILE__, array(self::class, 'activate'));
        register_deactivation_hook(__FILE__, array(self::class, 'deactivate'));

        if (!$this->plugin_is_configured()) {
            add_action('all_admin_notices', array($this, 'print_plugin_not_configured'));
            return;
        }

        add_action('login_init', array($this, 'register_session'), 10);
        add_filter('authenticate', array($this, 'authenticate'), 1, 3);
        add_action('login_enqueue_scripts', array($this, 'print_login_css'));
        add_action('login_form', array($this, 'print_login_link'));
        add_action('wp_logout', array($this, 'logout'));
        add_action('login_init', array($this, 'save_redirect_and_maybe_bypass_login'), 20);
        add_filter('login_redirect', array($this, 'redirect_after_login'), 20, 3);
        add_action('plugins_loaded', array($this, 'load_textdomain'));
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
                $_SESSION['aadsso_redirect_to'] = sanitize_url($_GET['redirect_to']);
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
            unset($_SESSION['aadsso_redirect_to']);
        }

        return $redirect_to;
    }

    private function wants_to_login(): bool
    {
        $action = isset($_REQUEST['action']) ? (string) $_REQUEST['action'] : 'login';
        if (isset($_GET['loggedout'])) {
            $action = 'loggedout';
        }
        return 'login' === $action;
    }

    public function authenticate($user, string $username, string $password)
    {
        if ($user instanceof WP_User) {
            return $user;
        }

        if (isset($_GET['code']) && is_string($_GET['code'])) {
            if (!isset($_SESSION['aadsso_antiforgery-id'])) {
                return new WP_Error(
                    'missing_antiforgery_id',
                    __('Session does not contain antiforgery ID.', 'aad-sso-wordpress')
                );
            }

            $antiforgery_id = (string) $_SESSION['aadsso_antiforgery-id'];
            $state_param = isset($_GET['state']) ? sanitize_text_field(wp_unslash($_GET['state'])) : '';

            if ('' === $state_param || $state_param !== $antiforgery_id) {
                return new WP_Error(
                    'antiforgery_id_mismatch',
                    sprintf(
                        __('ANTIFORGERY_ID mismatch. Expecting %s', 'aad-sso-wordpress'),
                        esc_html($antiforgery_id)
                    )
                );
            }

            $code = sanitize_text_field(wp_unslash($_GET['code']));
            $token = AADSSO_AuthorizationHelper::get_access_token($code, $this->settings);

            if (isset($token->access_token)) {
                try {
                    $jwt = AADSSO_AuthorizationHelper::validate_id_token(
                        (string) $token->id_token,
                        $this->settings,
                        $antiforgery_id
                    );

                    AADSSO::debug_log("ID Token: iss: '" . $jwt->iss . "', oid: '" . $jwt->oid, 10);
                    AADSSO::debug_log(wp_json_encode($jwt), 50);
                } catch (Exception $e) {
                    return new WP_Error(
                        'invalid_id_token',
                        sprintf(
                            __('ERROR: Invalid id_token. %s', 'aad-sso-wordpress'),
                            esc_html($e->getMessage())
                        )
                    );
                }

                $group_memberships = false;
                if (true === $this->settings->enable_aad_group_to_wp_role) {
                    AADSSO_GraphHelper::$settings = $this->settings;

                    $group_ids = array_keys($this->settings->aad_group_to_wp_role_map);
                    $group_memberships = AADSSO_GraphHelper::user_check_member_groups(
                        (string) $jwt->oid,
                        $group_ids
                    );

                    if (isset($group_memberships->value)) {
                        AADSSO::debug_log(sprintf(
                            "Microsoft Entra ID user '%s' is a member of [%s]",
                            $jwt->oid,
                            implode(',', $group_memberships->value)
                        ), 20);
                    } elseif (isset($group_memberships->error)) {
                        AADSSO::debug_log(
                            'Error when checking group membership: ' . wp_json_encode($group_memberships)
                        );
                        return new WP_Error(
                            'error_checking_group_membership',
                            sprintf(
                                __('ERROR: Unable to check group membership with Microsoft Graph: '
                                    . '<b>%s</b> %s<br />%s', 'aad-sso-wordpress'),
                                esc_html((string) ($group_memberships->error->code ?? '')),
                                esc_html((string) ($group_memberships->error->message ?? '')),
                                esc_html(wp_json_encode($group_memberships->error->innerError ?? null))
                            )
                        );
                    } else {
                        AADSSO::debug_log(
                            'Unexpected response to checkMemberGroups: ' . wp_json_encode($group_memberships)
                        );
                        return new WP_Error(
                            'unexpected_response_to_checkMemberGroups',
                            __('ERROR: Unexpected response when checking group membership with Microsoft Graph.',
                                'aad-sso-wordpress')
                        );
                    }
                }

                $user = $this->get_wp_user_from_aad_user($jwt, $group_memberships);

                if ($user instanceof WP_User && true === $this->settings->enable_aad_group_to_wp_role) {
                    $user = $this->update_wp_user_roles($user, $group_memberships);
                }
            } elseif (isset($token->error)) {
                return new WP_Error(
                    'token_error',
                    sprintf(
                        __('ERROR: Could not get an access token to Microsoft Graph. %s', 'aad-sso-wordpress'),
                        esc_html((string) ($token->error_description ?? $token->error))
                    )
                );
            } else {
                return new WP_Error(
                    'unknown',
                    __('ERROR: An unknown error occurred.', 'aad-sso-wordpress')
                );
            }
        } elseif (isset($_GET['error']) && is_string($_GET['error'])) {
            return new WP_Error(
                'oauth_error',
                sprintf(
                    __('ERROR: Access denied to Microsoft Graph. %s', 'aad-sso-wordpress'),
                    esc_html(sanitize_text_field(wp_unslash($_GET['error_description'] ?? $_GET['error'])))
                )
            );
        }

        if ($user instanceof WP_User) {
            $_SESSION['aadsso_signed_in_with_azuread'] = true;
        }

        return $user;
    }

    public function get_wp_user_from_aad_user($jwt, $group_memberships)
    {
        $upn = isset($jwt->upn) ? (string) $jwt->upn : null;
        $unique_name = isset($jwt->unique_name) ? (string) $jwt->unique_name : null;
        $unique_name = $upn ?? $unique_name;

        if (null === $unique_name) {
            return new WP_Error(
                'unique_name_not_found',
                __('ERROR: Neither \'upn\' nor \'unique_name\' claims found in ID Token.',
                    'aad-sso-wordpress')
            );
        }

        $user = get_user_by($this->settings->field_to_match_to_upn, $unique_name);

        if (true === $this->settings->match_on_upn_alias && !($user instanceof WP_User)) {
            $domain_hint = sanitize_text_field($this->settings->org_domain_hint);
            if (!empty($domain_hint)) {
                $parts = explode('@' . $domain_hint, $unique_name);
                if (count($parts) === 2) {
                    $username = trim($parts[0]);
                    $user = get_user_by($this->settings->field_to_match_to_upn, $username);
                }
            }
        }

        if ($user instanceof WP_User) {
            AADSSO::debug_log(sprintf(
                'Matched Microsoft Entra ID user [%s] to existing WordPress user [%s].',
                $unique_name,
                (string) $user->ID
            ), 10);
        } else {
            if (true === $this->settings->enable_auto_provisioning) {
                if (true === $this->settings->enable_aad_group_to_wp_role
                    && (empty($group_memberships->value) || !is_array($group_memberships->value))
                    && empty($this->settings->default_wp_role)
                ) {
                    return new WP_Error(
                        'user_not_assigned_to_group',
                        sprintf(
                            __('ERROR: Access denied. You\'re not a member of any group granting you '
                                . 'access to this site. You\'re signed in as \'%s\'.', 'aad-sso-wordpress'),
                            esc_html($unique_name)
                        )
                    );
                }

                $userdata = array(
                    'user_email' => sanitize_email($unique_name),
                    'user_login' => sanitize_user($unique_name, true),
                    'first_name' => !empty($jwt->given_name) ? sanitize_text_field((string) $jwt->given_name) : '',
                    'last_name' => !empty($jwt->family_name) ? sanitize_text_field((string) $jwt->family_name) : '',
                    'user_pass' => null,
                );

                $new_user_id = wp_insert_user($userdata);

                if (is_wp_error($new_user_id)) {
                    return new WP_Error(
                        'user_not_registered',
                        sprintf(
                            __('ERROR: Error creating user \'%s\'.', 'aad-sso-wordpress'),
                            esc_html($unique_name)
                        )
                    );
                }

                AADSSO::debug_log("Created new user: '" . $unique_name . "', user id " . $new_user_id . ".");
                $user = new WP_User($new_user_id);
            } else {
                return new WP_Error(
                    'user_not_registered',
                    sprintf(
                        __('ERROR: The authenticated user \'%s\' is not a registered user in this site.',
                            'aad-sso-wordpress'),
                        esc_html($unique_name)
                    )
                );
            }
        }

        return $user;
    }

    public function update_wp_user_roles(WP_User $user, $group_memberships): WP_User
    {
        $roles_to_set = array();

        if (!empty($group_memberships->value) && is_array($group_memberships->value)) {
            foreach ($this->settings->aad_group_to_wp_role_map as $aad_group => $wp_role) {
                if (in_array($aad_group, $group_memberships->value, true)) {
                    $roles_to_set[] = $wp_role;
                }
            }
        }

        if (!empty($roles_to_set)) {
            $user->set_role('');
            foreach ($roles_to_set as $role) {
                $user->add_role($role);
            }
            AADSSO::debug_log(sprintf(
                'Set roles [%s] for user [%s].',
                implode(', ', $roles_to_set),
                (string) $user->ID
            ), 10);
        } elseif (!empty($this->settings->default_wp_role)) {
            $user->set_role((string) $this->settings->default_wp_role);
            AADSSO::debug_log(sprintf(
                'Set default role [%s] for user [%s].',
                (string) $this->settings->default_wp_role,
                (string) $user->ID
            ), 10);
        } else {
            $error_message = sprintf(
                __('ERROR: Microsoft Entra ID user %s is not a member of any group granting a role.',
                    'aad-sso-wordpress'),
                (string) $user->ID
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
            . '?' . http_build_query(array('post_logout_redirect_uri' => $logout_redirect_uri));
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
            . esc_html__(
                'Single Sign-on with Microsoft Entra ID required settings are not defined. '
                . 'Update them under Settings > Microsoft Entra ID.',
                'aad-sso-wordpress'
            ) . '</p></div>';
    }

    public function print_debug(): void
    {
        echo '<p>SESSION</p><pre>' . esc_html(var_export($_SESSION, true)) . '</pre>';
        echo '<p>GET</p><pre>' . esc_html(var_export($_GET, true)) . '</pre>';
        echo '<p>Database settings</p><pre>' . esc_html(var_export(get_option('aadsso_settings'), true)) . '</pre>';
        echo '<p>Plugin settings</p><pre>' . esc_html(var_export($this->settings, true)) . '</pre>';
    }

    public function print_login_css(): void
    {
        wp_enqueue_style(AADSSO, AADSSO_PLUGIN_URL . '/login.css');
    }

    public function print_login_link(): void
    {
        $org_name = !empty($this->settings->org_display_name)
            ? esc_html($this->settings->org_display_name)
            : esc_html__('Organization', 'aad-sso-wordpress');

        printf(
            '<p class="aadsso-login-form-text">'
            . '<a href="%s">%s</a><br />'
            . '<a class="dim" href="%s">%s</a></p>',
            esc_url($this->get_login_url()),
            sprintf(
                esc_html__('Sign in with your %s account', 'aad-sso-wordpress'),
                $org_name
            ),
            esc_url($this->get_logout_url()),
            esc_html__('Sign out', 'aad-sso-wordpress')
        );
    }

    public static function debug_log($message, int $level = 0): void
    {
        do_action('aadsso_debug_log', $message);

        $debug_enabled = apply_filters('aadsso_debug', AADSSO_DEBUG);
        $debug_level = apply_filters('aadsso_debug_level', AADSSO_DEBUG_LEVEL);

        if (true === $debug_enabled && $debug_level >= $level) {
            $formatted_message = 'AADSSO: ' . (is_string($message) ? $message : wp_json_encode($message));
            error_log($formatted_message);
        }
    }

    public static function debug_print_backtrace(int $level = 10): void
    {
        ob_start();
        debug_print_backtrace();
        $trace = ob_get_clean();
        self::debug_log($trace, $level);
    }
}

if (!function_exists('aad_sso_create_uuid')) {
    function aad_sso_create_uuid(): string
    {
        $random_bytes = random_bytes(16);

        $random_bytes[6] = chr(ord($random_bytes[6]) & 0x0f | 0x40);
        $random_bytes[8] = chr(ord($random_bytes[8]) & 0x3f | 0x80);

        return vsprintf(
            '%s%s-%s-%s-%s-%s%s%s',
            str_split(bin2hex($random_bytes), 4)
        );
    }
}

$aadsso_settings_instance = AADSSO_Settings::init();
$aadsso = AADSSO::get_instance($aadsso_settings_instance);