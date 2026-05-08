<?php

/**
 * Plugin Name: Single Sign-on with Microsoft Entra ID
 * Plugin URI:  https://github.com/Voornaamenachternaam/aad-sso-wordpress-ng
 * Description: Allows organizations to use their Microsoft Entra ID (formerly Azure AD) user accounts to sign in to WordPress.
 * Version:     0.9.0
 * Author:      Voornaamenachternaam
 * Author URI:  https://github.com/Voornaamenachternaam
 * License:     MIT
 * License URI: https://github.com/Voornaamenachternaam/aad-sso-wordpress-ng/blob/master/LICENSE.md
 * Text Domain: aad-sso-wordpress-ng
 * Domain Path: /languages
 * Requires at least: 6.9.4
 * Tested up to: 6.9.4
 * Requires PHP: 8.5.5
 */

declare(strict_types=1);

\defined('ABSPATH') || exit;

$autoloader = __DIR__ . '/vendor/autoload.php';
if (file_exists($autoloader)) {
    require_once $autoloader;
}

\define('AADSSO', 'aad-sso-wordpress');
\define('AADSSO_PLUGIN_URL', plugin_dir_url(__FILE__));
\define('AADSSO_PLUGIN_DIR', plugin_dir_path(__FILE__));

\defined('AADSSO_DEBUG') || \define('AADSSO_DEBUG', false);
\defined('AADSSO_DEBUG_LEVEL') || \define('AADSSO_DEBUG_LEVEL', 0);

require_once AADSSO_PLUGIN_DIR . '/Settings.php';
require_once AADSSO_PLUGIN_DIR . '/SettingsPage.php';
require_once AADSSO_PLUGIN_DIR . '/AuthorizationHelper.php';
require_once AADSSO_PLUGIN_DIR . '/GraphHelper.php';
require_once AADSSO_PLUGIN_DIR . '/Logger.php';
require_once AADSSO_PLUGIN_DIR . '/HttpClient.php';

class AADSSO
{
    private static ?AADSSO $instance = null;

    private AADSSO_Settings $settings;

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

    public static function deactivate(): void {}

    public function load_textdomain(): void
    {
        load_plugin_textdomain(
            'aad-sso-wordpress',
            false,
            \dirname(plugin_basename(__FILE__)) . '/languages/'
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
            'aadsso_auto_forward_login',
            $this->settings->enable_auto_forward_to_aad
        );

        if (isset($_GET['aadsso_no_redirect'])) {
            AADSSO_Logger::log_info('Skipping automatic redirects to Microsoft Entra ID.');
            $auto_redirect = false;
        }

        if ($this->wants_to_login()) {
            if (isset($_GET['redirect_to']) && \is_string($_GET['redirect_to'])) {
                $_SESSION['aadsso_redirect_to'] = sanitize_url($_GET['redirect_to']);
            }

            if ($auto_redirect && !isset($_GET['code']) && !isset($_POST['log'])) {
                wp_safe_redirect($this->get_login_url());
                exit;
            }
        }
    }

    public function redirect_after_login(string $redirect_to, string $requested_redirect_to, ?WP_User $user): string
    {
        if ($user instanceof WP_User && isset($_SESSION['aadsso_redirect_to'])) {
            $redirect_raw = $_SESSION['aadsso_redirect_to'];
            $redirect_to = \is_string($redirect_raw) ? sanitize_url($redirect_raw) : $redirect_to;
            unset($_SESSION['aadsso_redirect_to']);
        }

        return $redirect_to;
    }

    public function authenticate(mixed $user, ?string $username, ?string $password): WP_User|WP_Error|null
    {
        if ($user instanceof WP_User) {
            return $user;
        }

        if (isset($_GET['code']) && \is_string($_GET['code'])) {
            if (!isset($_SESSION['aadsso_antiforgery-id'])) {
                return new WP_Error(
                    'missing_antiforgery_id',
                    __('Session does not contain antiforgery ID.', 'aad-sso-wordpress')
                );
            }

            $antiforgery_id_raw = $_SESSION['aadsso_antiforgery-id'];
            /** @var string $antiforgery_id_raw */
            $antiforgery_id = \is_string($antiforgery_id_raw) ? $antiforgery_id_raw : '';
            $state_param = isset($_GET['state']) && \is_string($_GET['state']) ? (string) wp_unslash($_GET['state']) : '';

            if ('' === $state_param || $state_param !== $antiforgery_id) {
                return new WP_Error(
                    'antiforgery_id_mismatch',
                    \sprintf(
                        __('ANTIFORGERY_ID mismatch. Expecting %s', 'aad-sso-wordpress'),
                        esc_html($antiforgery_id)
                    )
                );
            }

            $code = (string) wp_unslash($_GET['code']);
            /** @var mixed */
            $token_raw = AADSSO_AuthorizationHelper::get_access_token($code, $this->settings);

            if (is_wp_error($token_raw)) {
                /** @var WP_Error $token */
                $token = $token_raw;
                AADSSO_Logger::log_error('Token request failed: ' . $token->get_error_message());

                return new WP_Error(
                    'token_request_failed',
                    \sprintf(
                        __('ERROR: Could not get an access token to Microsoft Graph. %s', 'aad-sso-wordpress'),
                        esc_html($token->get_error_message() ?: '')
                    )
                );
            }

            /** @var stdClass $token */
            $token = (object) $token_raw;
            if (!isset($token->access_token)) {
                AADSSO_Logger::log_error('Token response missing access_token');

                return new WP_Error(
                    'invalid_token_response',
                    __('ERROR: Invalid token response from Microsoft Entra ID.', 'aad-sso-wordpress')
                );
            }

            /** @var mixed */
            $id_token_raw = $token->id_token ?? '';
            $id_token_str = \is_string($id_token_raw) ? $id_token_raw : '';

            $jwt = null;
            try {
                $jwt = AADSSO_AuthorizationHelper::validate_id_token(
                    $id_token_str,
                    $this->settings,
                    $antiforgery_id
                );
            } catch (Throwable $e) {
                AADSSO_Logger::log_error('ID token validation failed: ' . $e->getMessage());

                return new WP_Error(
                    'id_token_validation_failed',
                    \sprintf(
                        __('ERROR: ID token validation failed. %s', 'aad-sso-wordpress'),
                        esc_html($e->getMessage())
                    )
                );
            }

            /** @var stdClass $jwt */
            $jwt = $jwt;

            $jwt_iss = isset($jwt->iss) && \is_string($jwt->iss) ? $jwt->iss : '';
            $jwt_oid = isset($jwt->oid) && \is_string($jwt->oid) ? $jwt->oid : '';
            AADSSO_Logger::log_debug("ID Token: iss: '" . $jwt_iss . "', oid: '" . $jwt_oid . "'", 10);

            // Validate issuer claim to prevent token substitution attacks
            // The issuer must exactly match the expected issuer from OpenID configuration
            // or follow the correct pattern for the configured tenant
            $expected_issuer = $this->settings->issuer;
            if (!empty($expected_issuer)) {
                // For single-tenant deployments: exact match required
                // The issuer should be exactly: https://login.microsoftonline.com/{tenant-id}/v2.0
                if ($jwt_iss !== $expected_issuer) {
                    AADSSO_Logger::log_error(\sprintf(
                        'Issuer mismatch: expected "%s", got "%s"',
                        $expected_issuer,
                        $jwt_iss
                    ));

                    return new WP_Error(
                        'invalid_token_issuer',
                        __('ERROR: Token issuer validation failed. This may indicate a token substitution attack.', 'aad-sso-wordpress')
                    );
                }
            } else {
                // Fallback validation if issuer not configured yet
                // Check that issuer follows Microsoft Entra ID v2.0 pattern
                // Valid patterns:
                // - https://login.microsoftonline.com/{tenant-id}/v2.0 (single tenant)
                // - https://login.microsoftonline.com/{domain}/v2.0 (domain-based tenant)
                // - https://login.microsoftonline.com/common/v2.0 (multi-tenant with /common)
                // - https://login.microsoftonline.com/organizations/v2.0 (multi-tenant with /organizations)
                if (!empty($jwt_iss)) {
                    $issuer_valid = preg_match(
                        '#^https://login\.microsoftonline\.com/[^/]+/v2\.0$#',
                        $jwt_iss
                    );
                    if (!$issuer_valid) {
                        AADSSO_Logger::log_error(\sprintf(
                            'Invalid issuer format: "%s". Expected Microsoft Entra ID v2.0 issuer pattern.',
                            $jwt_iss
                        ));

                        return new WP_Error(
                            'invalid_token_issuer',
                            __('ERROR: Token issuer has invalid format. This may indicate a token substitution attack.', 'aad-sso-wordpress')
                        );
                    }
                }
            }

            $group_memberships = false;
            if (true === $this->settings->enable_aad_group_to_wp_role) {
                AADSSO_GraphHelper::$settings = $this->settings;

                $group_ids = array_keys($this->settings->aad_group_to_wp_role_map);
                $jwt_oid = isset($jwt->oid) && \is_string($jwt->oid) ? $jwt->oid : '';
                $group_result = AADSSO_GraphHelper::user_check_member_groups(
                    $jwt_oid,
                    $group_ids
                );

                // Check for WP_Error from Graph API call
                if (is_wp_error($group_result)) {
                    $group_memberships = $group_result;
                    AADSSO_Logger::log_error('Graph API error: ' . $group_memberships->get_error_message());

                    return new WP_Error(
                        'graph_api_error',
                        \sprintf(
                            __('ERROR: Unable to check group membership with Microsoft Graph: %s', 'aad-sso-wordpress'),
                            esc_html($group_memberships->get_error_message() ?: '')
                        )
                    );
                }

                $group_memberships = $group_result;
                /** @var stdClass $group_memberships */
                if (isset($group_memberships->value) && \is_array($group_memberships->value)) {
                    $group_values = array_values(array_filter($group_memberships->value, 'is_string'));
                    AADSSO_Logger::log_debug(\sprintf(
                        "Microsoft Entra ID user '%s' is a member of [%s]",
                        $jwt_oid,
                        implode(',', $group_values)
                    ), 20);
                } elseif (isset($group_memberships->error) && \is_object($group_memberships->error)) {
                    AADSSO_Logger::log_error(
                        'Error when checking group membership: ' . wp_json_encode($group_memberships)
                    );
                    $error_obj = $group_memberships->error;
                    $error_code = isset($error_obj->code) && \is_string($error_obj->code) ? $error_obj->code : '';
                    $error_message = isset($error_obj->message) && \is_string($error_obj->message) ? $error_obj->message : '';
                    $error_inner = $error_obj->innerError ?? null;
                    $error_inner_json = \is_string($error_inner) ? $error_inner : (wp_json_encode($error_inner) ?: '');

                    return new WP_Error(
                        'error_checking_group_membership',
                        \sprintf(
                            __('ERROR: Unable to check group membership with Microsoft Graph: '
                                . '<b>%s</b> %s<br />%s', 'aad-sso-wordpress'),
                            esc_html($error_code),
                            esc_html($error_message),
                            esc_html($error_inner_json)
                        )
                    );
                } else {
                    AADSSO_Logger::log_warning(
                        'Unexpected response to checkMemberGroups: ' . wp_json_encode($group_memberships)
                    );

                    return new WP_Error(
                        'unexpected_response_to_checkMemberGroups',
                        __(
                            'ERROR: Unexpected response when checking group membership with Microsoft Graph.',
                            'aad-sso-wordpress'
                        )
                    );
                }
            }

            $user = $this->get_wp_user_from_aad_user($jwt, $group_memberships);

            if ($user instanceof WP_User && true === $this->settings->enable_aad_group_to_wp_role) {
                $role_result = $this->update_wp_user_roles($user, $group_memberships);
                if ($role_result instanceof WP_Error) {
                    return $role_result;
                }
                $user = $role_result;
            }
        } elseif (isset($_GET['error']) && \is_string($_GET['error'])) {
            $error_desc_raw = $_GET['error_description'] ?? $_GET['error'];
            $error_desc = \is_string($error_desc_raw) ? sanitize_text_field(wp_unslash($error_desc_raw)) : '';

            return new WP_Error(
                'oauth_error',
                \sprintf(
                    __('ERROR: Access denied to Microsoft Graph. %s', 'aad-sso-wordpress'),
                    esc_html($error_desc)
                )
            );
        }

        if ($user instanceof WP_User) {
            $_SESSION['aadsso_signed_in_with_entra_id'] = true;
        }

        // @var WP_User|null
        return $user;
    }

    public function get_wp_user_from_aad_user(object $jwt, mixed $group_memberships): WP_User|WP_Error
    {
        /** @var mixed */
        $upn_raw = $jwt->upn ?? null;
        $upn = \is_string($upn_raw) ? $upn_raw : null;
        /** @var mixed */
        $unique_name_raw = $jwt->unique_name ?? null;
        $unique_name = \is_string($unique_name_raw) ? $unique_name_raw : $upn;

        // Collect all possible email/identifier claims for matching
        // Priority: email > preferred_username > upn > unique_name
        // Note: 'mail' is not a standard ID token claim - it's a Graph API attribute
        /** @var null|string */
        $email_claim = null;
        /** @var mixed */
        $email_raw = $jwt->email ?? null;
        if (\is_string($email_raw)) {
            $email_claim = $email_raw;
        }
        // Note: preferred_username is snake_case (OpenID Connect standard)
        /** @var mixed */
        $preferred_username_raw = $jwt->preferred_username ?? null;
        if (null === $email_claim && \is_string($preferred_username_raw)) {
            // For guest users, preferred_username often contains their actual email
            // (while upn contains the #EXT# format)
            $email_claim = $preferred_username_raw;
        }

        // Log available claims for debugging
        /** @var mixed */
        $log_preferred_username = $jwt->preferred_username ?? '(null)';
        /** @var mixed */
        $log_mail = $jwt->mail ?? '(null)';
        AADSSO_Logger::log_debug(\sprintf(
            'User claims: upn=%s, unique_name=%s, email=%s, preferred_username=%s, mail=%s',
            $upn ?? '(null)',
            $unique_name ?? '(null)',
            $email_claim ?? '(null)',
            \is_string($log_preferred_username) ? $log_preferred_username : '(non-string)',
            \is_string($log_mail) ? $log_mail : '(non-string)'
        ), 10);

        if (null === $unique_name) {
            return new WP_Error(
                'unique_name_not_found',
                __(
                    'ERROR: Neither \'upn\' nor \'unique_name\' claims found in ID Token.',
                    'aad-sso-wordpress'
                )
            );
        }

        // Determine which field to match
        $match_field = $this->settings->field_to_match_to_upn;
        $match_value = $unique_name;

        // If matching by email and we have an email claim, prefer that over UPN
        if ('email' === $match_field && null !== $email_claim) {
            $match_value = $email_claim;
        }

        $user = get_user_by($match_field, $match_value);

        // If no match by primary value, try fallback with email claim if different
        if (!($user instanceof WP_User) && null !== $email_claim && $email_claim !== $match_value) {
            $user = get_user_by($match_field, $email_claim);
            if ($user instanceof WP_User) {
                AADSSO_Logger::log_debug(\sprintf(
                    'Matched user by email claim (%s) instead of primary value (%s).',
                    $email_claim,
                    $match_value
                ), 10);
            }
        }

        // Try UPN alias matching if enabled and still no match
        if (true === $this->settings->match_on_upn_alias && !($user instanceof WP_User)) {
            $domain_hint = sanitize_text_field($this->settings->org_domain_hint);
            if (!empty($domain_hint)) {
                $parts = explode('@' . $domain_hint, $unique_name);
                if (2 === \count($parts)) {
                    $username = mb_trim($parts[0]);
                    $user = get_user_by($this->settings->field_to_match_to_upn, $username);
                }
            }
        }

        // Final fallback: try matching by any known identifier
        if (!($user instanceof WP_User) && null !== $email_claim) {
            // Try with all lowercase (some systems normalize emails)
            $user = get_user_by($match_field, mb_strtolower($email_claim));
            if (!($user instanceof WP_User)) {
                $user = get_user_by($match_field, mb_strtolower($unique_name));
            }
        }

        if ($user instanceof WP_User) {
            // Warn if email in WordPress doesn't match Entra ID email claim
            if (null !== $email_claim && $user->user_email !== $email_claim) {
                AADSSO_Logger::log_warning(\sprintf(
                    'Email mismatch for user %d: WordPress has %s, Entra ID has %s. '
                    . 'Consider updating the user email to ensure consistency.',
                    $user->ID,
                    $user->user_email,
                    $email_claim
                ), 10);
            }

            AADSSO_Logger::log_debug(\sprintf(
                'Matched Microsoft Entra ID user [%s] to existing WordPress user [%s].',
                $unique_name,
                (string) $user->ID
            ), 10);
        } else {
            if (true === $this->settings->enable_auto_provisioning) {
                /** @var stdClass $group_memberships */
                $has_group_memberships = false !== $group_memberships
                    && isset($group_memberships->value)
                    && \is_array($group_memberships->value);
                if (true === $this->settings->enable_aad_group_to_wp_role
                    && (!$has_group_memberships)
                    && empty($this->settings->default_wp_role)
                ) {
                    return new WP_Error(
                        'user_not_assigned_to_group',
                        \sprintf(
                            __('ERROR: Access denied. You\'re not a member of any group granting you '
                                . 'access to this site. You\'re signed in as \'%s\'.', 'aad-sso-wordpress'),
                            esc_html($unique_name)
                        )
                    );
                }

                /** @var mixed */
                $given_name_raw = $jwt->given_name ?? '';
                $given_name = \is_string($given_name_raw) ? sanitize_text_field($given_name_raw) : '';
                /** @var mixed */
                $family_name_raw = $jwt->family_name ?? '';
                $family_name = \is_string($family_name_raw) ? sanitize_text_field($family_name_raw) : '';

                // Use email claim for new user email if available, otherwise use unique_name
                $user_email = null !== $email_claim ? sanitize_email($email_claim) : sanitize_email($unique_name);
                // Ensure email is valid before using it
                if (!is_email($user_email)) {
                    $user_email = sanitize_email($unique_name);
                }

                $userdata = [
                    'user_email' => $user_email,
                    'user_login' => sanitize_user($unique_name, true),
                    'first_name' => $given_name,
                    'last_name' => $family_name,
                ];

                $new_user_id = wp_insert_user($userdata);

                if (is_wp_error($new_user_id)) {
                    return new WP_Error(
                        'user_not_registered',
                        \sprintf(
                            __('ERROR: Error creating user \'%s\'.', 'aad-sso-wordpress'),
                            esc_html($unique_name)
                        )
                    );
                }

                AADSSO_Logger::log_info("Created new user: '" . $unique_name . "', user id " . $new_user_id . '.');
                $user = new WP_User($new_user_id);
            } else {
                return new WP_Error(
                    'user_not_registered',
                    \sprintf(
                        __(
                            'ERROR: The authenticated user \'%s\' is not a registered user in this site.',
                            'aad-sso-wordpress'
                        ),
                        esc_html($unique_name)
                    )
                );
            }
        }

        return $user;
    }

    public function update_wp_user_roles(WP_User $user, mixed $group_memberships): WP_User|WP_Error
    {
        /** @var list<string> $roles_to_set */
        $roles_to_set = [];

        if (
            false !== $group_memberships
            && \is_object($group_memberships)
            && isset($group_memberships->value)
            && \is_array($group_memberships->value)
        ) {
            /** @var non-empty-list<string> $groupList */
            $groupList = $group_memberships->value;
            foreach ($this->settings->aad_group_to_wp_role_map as $aad_group => $wp_role) {
                if (\is_string($wp_role) && \in_array($aad_group, $groupList, true)) {
                    $roles_to_set[] = $wp_role;
                }
            }
        }

        if (!empty($roles_to_set)) {
            $user->set_role('');
            foreach ($roles_to_set as $role) {
                $user->add_role($role);
            }
            AADSSO_Logger::log_debug(\sprintf(
                'Set roles [%s] for user [%s].',
                implode(', ', $roles_to_set),
                $user->ID
            ), 10);
        } elseif (!empty($this->settings->default_wp_role)) {
            $user->set_role($this->settings->default_wp_role);
            AADSSO_Logger::log_debug(\sprintf(
                'Set default role [%s] for user [%s].',
                (string) $this->settings->default_wp_role,
                (string) $user->ID
            ), 10);
        } else {
            $error_message = \sprintf(
                __(
                    'ERROR: Microsoft Entra ID user %s is not a member of any group granting a role.',
                    'aad-sso-wordpress'
                ),
                (string) $user->ID
            );
            AADSSO_Logger::log_warning($error_message);

            return new WP_Error('user_not_member_of_required_group', $error_message);
        }

        return $user;
    }

    /**
     * @param array<string, string> $links
     *
     * @return array<string, string>
     */
    public function add_settings_link(array $links): array
    {
        $new_link = '<a href="' . esc_url(admin_url('options-general.php?page=aadsso_settings')) . '">'
            . esc_html__('Settings', 'aad-sso-wordpress') . '</a>';
        // @var array<string, string> $links
        $links['aadsso_settings'] = $new_link;

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
            $default_logout = AADSSO_Settings::get_defaults('logout_redirect_uri');
            $logout_redirect_uri = \is_string($default_logout) ? $default_logout : wp_login_url();
        }

        $end_session = $this->settings->end_session_endpoint;
        if (empty($end_session)) {
            return $logout_redirect_uri;
        }

        return $end_session
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
            session_destroy();
        }
    }

    public function logout(): void
    {
        $signed_in_with_entra_id = isset($_SESSION['aadsso_signed_in_with_entra_id'])
            && true === $_SESSION['aadsso_signed_in_with_entra_id'];
        $this->clear_session();

        if ($signed_in_with_entra_id && $this->settings->enable_full_logout) {
            wp_safe_redirect($this->get_logout_url());
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
        $org_name = '';
        if (!empty($this->settings->org_display_name) && \is_string($this->settings->org_display_name)) {
            $org_name = esc_html($this->settings->org_display_name);
        } else {
            $org_name = esc_html__('Organization', 'aad-sso-wordpress');
        }

        printf(
            '<p class="aadsso-login-form-text">'
            . '<a href="%s">%s</a><br />'
            . '<a class="dim" href="%s">%s</a></p>',
            esc_url($this->get_login_url()),
            \sprintf(
                esc_html__('Sign in with your %s account', 'aad-sso-wordpress'),
                $org_name
            ),
            esc_url($this->get_logout_url()),
            esc_html__('Sign out', 'aad-sso-wordpress')
        );
    }

    /**
     * @param mixed $message
     */
    public static function debug_log(mixed $message, int $level = 0): void
    {
        do_action('aadsso_debug_log', $message);

        $debug_enabled = apply_filters('aadsso_debug', AADSSO_DEBUG);
        $debug_level = apply_filters('aadsso_debug_level', AADSSO_DEBUG_LEVEL);

        // Handle both boolean and string "true" for compatibility
        $is_enabled = filter_var($debug_enabled, \FILTER_VALIDATE_BOOLEAN);

        if ($is_enabled && $debug_level >= $level) {
            $formatted_message = 'AADSSO: ' . (\is_string($message) ? $message : wp_json_encode($message));
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

    private function wants_to_login(): bool
    {
        $action_raw = $_REQUEST['action'] ?? 'login';
        $action = \is_string($action_raw) ? sanitize_text_field(wp_unslash($action_raw)) : 'login';
        if (isset($_GET['loggedout'])) {
            $action = 'loggedout';
        }

        return 'login' === $action;
    }
}

if (!\function_exists('aad_sso_create_uuid')) {
    function aad_sso_create_uuid(): string
    {
        $random_bytes = random_bytes(16);

        $random_bytes[6] = \chr(\ord($random_bytes[6]) & 0x0F | 0x40);
        $random_bytes[8] = \chr(\ord($random_bytes[8]) & 0x3F | 0x80);

        return vsprintf(
            '%s%s-%s-%s-%s-%s%s%s',
            mb_str_split(bin2hex($random_bytes), 4)
        );
    }
}

$aadsso_settings_instance = AADSSO_Settings::init();
$aadsso = AADSSO::get_instance($aadsso_settings_instance);
