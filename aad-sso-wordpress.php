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
 * Requires PHP: 8.4
 */

declare(strict_types=1);

\defined('ABSPATH') || exit;

// ─────────────────────────────────────────────────────────────────────────────
// PHP Version Requirement Check
//
// This plugin requires PHP 8.4.0 or higher. This check must run before any
// other plugin code to prevent fatal errors on incompatible PHP versions.
//
// Note: WordPress plugin headers alone may not prevent activation on older PHP
// versions in all configurations. A runtime check provides defense-in-depth.
// ─────────────────────────────────────────────────────────────────────────────
const AADSSO_MIN_PHP_VERSION = '8.4.0';

if (version_compare(\PHP_VERSION, AADSSO_MIN_PHP_VERSION, '<')) {
    /*
     * Fires before the plugin is loaded for displaying PHP version error.
     * Using add_action ensures WordPress is initialized enough for wp_die().
     */
    add_action('init', static function (): void {
        if (!\defined('AADSSO_VERSION_CHECK_FAILED')) {
            \define('AADSSO_VERSION_CHECK_FAILED', true);
            wp_die(
                '<p>' . esc_html__(
                    'Single Sign-on with Microsoft Entra ID requires PHP '
                    . AADSSO_MIN_PHP_VERSION
                    . ' or higher. You are running PHP '
                    . \PHP_VERSION
                    . '.',
                    'aad-sso-wordpress'
                ) . '</p>'
                . '<p>' . esc_html__(
                    'Please contact your hosting provider to upgrade PHP.',
                    'aad-sso-wordpress'
                ) . '</p>',
                esc_html__('PHP Version Error', 'aad-sso-wordpress'),
                ['response' => 500, 'back_link' => true]
            );
        }
    }, 1);

    return;
}

// ─────────────────────────────────────────────────────────────────────────────
// mb_rtrim() and mb_trim() Polyfills
//
// Both mb_rtrim() and mb_trim() were introduced in PHP 8.4.0. These polyfills
// provide compatibility for environments where they may not be available
// (e.g., custom mbstring builds, embedded PHP, or future PHP versions).
//
// mb_trim() is a multibyte-aware version of trim() that removes:
// - Leading and trailing whitespace (when $characters is null)
// - Leading and trailing characters specified in $characters
//
// References:
// - https://www.php.net/manual/en/function.mb-trim.php
// - https://wiki.php.net/rfc/mb_trim
// ─────────────────────────────────────────────────────────────────────────────
if (!\function_exists('mb_rtrim')) {
    /**
     * Multibyte-safe right trim.
     *
     * @param string      $string     The string to trim
     * @param null|string $characters Optional characters to trim (default: whitespace)
     *
     * @return string The trimmed string
     */
    function mb_rtrim(string $string, ?string $characters = null): string
    {
        if ('' === $string) {
            return '';
        }

        if (null === $characters) {
            return mb_rtrim($string);
        }

        // Handle the case where $characters is an empty string (no trimming)
        if ('' === $characters) {
            return $string;
        }

        // Use rtrim with the specified characters
        return mb_rtrim($string, $characters);
    }
}

if (!\function_exists('mb_trim')) {
    /**
     * Multibyte-safe trim.
     *
     * @param string      $string     The string to trim
     * @param null|string $characters Optional characters to trim (default: whitespace)
     *
     * @return string The trimmed string
     */
    function mb_trim(string $string, ?string $characters = null): string
    {
        if ('' === $string) {
            return '';
        }

        if (null === $characters) {
            return mb_trim($string);
        }

        // Handle the case where $characters is an empty string (no trimming)
        if ('' === $characters) {
            return $string;
        }

        // Use trim with the specified characters
        return mb_trim($string, $characters);
    }
}

$autoloader = __DIR__ . '/vendor/autoload.php';
if (file_exists($autoloader)) {
    require_once $autoloader;
}

\define('AADSSO', 'aad-sso-wordpress');
\define('AADSSO_PLUGIN_URL', plugin_dir_url(__FILE__));
\define('AADSSO_PLUGIN_DIR', plugin_dir_path(__FILE__));
\define('AADSSO_VERSION', '0.9.0');

\defined('AADSSO_DEBUG') || \define('AADSSO_DEBUG', false);
\defined('AADSSO_DEBUG_LEVEL') || \define('AADSSO_DEBUG_LEVEL', 0);

// Load core dependencies first (order matters: Logger has no deps, HttpClient depends on Logger, Settings depends on both)
// Note: These files use class_alias to provide prefixed names (e.g., AADSSO_Settings). The Composer autoloader
// cannot resolve these aliased names until the corresponding files are loaded, so manual require_once is used
// to ensure correct initialization order and avoid autoloader conflicts with the class_alias pattern.
require_once AADSSO_PLUGIN_DIR . '/Logger.php';
require_once AADSSO_PLUGIN_DIR . '/HttpClient.php';

// Settings depends on Logger and HttpClient
require_once AADSSO_PLUGIN_DIR . '/Settings.php';

// SettingsPage depends on Settings and Logger
require_once AADSSO_PLUGIN_DIR . '/SettingsPage.php';

// OAuth helpers depend on Logger and HttpClient
require_once AADSSO_PLUGIN_DIR . '/AuthorizationHelper.php';
require_once AADSSO_PLUGIN_DIR . '/GraphHelper.php';

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

        if (isset($this->settings->enable_safe_debug_mode)) {
            AADSSO_Logger::set_safe_debug_mode($this->settings->enable_safe_debug_mode);
        }
    }

    public static function activate(): void
    {
        $previous_version = get_option('aadsso_version', null);

        // Store previous endpoint before any cache invalidation
        $previous_endpoint = get_option('aadsso_settings', []);
        if (\is_array($previous_endpoint) && isset($previous_endpoint['openid_configuration_endpoint'])) {
            update_option('aadsso_previous_openid_endpoint', $previous_endpoint['openid_configuration_endpoint']);
        }

        // Invalidate OpenID configuration cache on every activation/upgrade
        // This ensures the new endpoint (if changed) is used immediately
        AADSSO_Settings::invalidate_openid_configuration_cache();

        $stored_settings = get_option('aadsso_settings', null);
        if (null === $stored_settings) {
            update_option('aadsso_settings', AADSSO_Settings::get_defaults());
        }

        // Store version for future upgrade migrations
        update_option('aadsso_version', AADSSO_VERSION);

        // If this is an upgrade (not fresh install), log migration notice
        if (null !== $previous_version && AADSSO_VERSION !== $previous_version) {
            AADSSO_Logger::log_info(\sprintf(
                'Plugin upgraded from %s to %s. OpenID configuration cache invalidated.',
                $previous_version,
                AADSSO_VERSION
            ));
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
                // First validate against configured security policies
                // Then sanitize as defense-in-depth before storing in session
                $validated_redirect = AADSSO_Settings::validate_redirect_url($_GET['redirect_to']);
                if ('' !== $validated_redirect) {
                    // Apply WordPress sanitization as additional defense-in-depth
                    $_SESSION['aadsso_redirect_to'] = sanitize_url($validated_redirect);
                }
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
            // Re-validate the stored redirect URL (defense in depth)
            $validated_redirect = AADSSO_Settings::validate_redirect_url($redirect_raw);
            if ('' !== $validated_redirect) {
                $redirect_to = $validated_redirect;
            }
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
            // Check for required session data (antiforgery + PKCE)
            if (!isset($_SESSION['aadsso_antiforgery-id'])) {
                return new WP_Error(
                    'missing_antiforgery_id',
                    __('Session does not contain antiforgery ID.', 'aad-sso-wordpress')
                );
            }

            // PKCE code_verifier is required for token exchange
            // This binds the token exchange to the original authorization request
            if (!isset($_SESSION['aadsso_pkce_code_verifier'])) {
                AADSSO_Logger::log_error('Session does not contain PKCE code_verifier');

                return new WP_Error(
                    'missing_pkce_verifier',
                    __('Session does not contain PKCE code verifier. This may indicate a session timeout or security issue.', 'aad-sso-wordpress')
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
            $code_verifier = $_SESSION['aadsso_pkce_code_verifier'];

            /** @var mixed */
            $token_raw = AADSSO_AuthorizationHelper::get_access_token($code, $this->settings, $code_verifier);

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

            // ─────────────────────────────────────────────────────────────────
            // Tenant ID (tid) validation - F-02 remediation
            //
            // Per Microsoft identity platform guidance (as of May 2026):
            // "Always check that the tid in a token matches the tenant ID used
            // to store data with the application. When information is stored
            // for an application in the context of a tenant, it should only be
            // accessed again later in the same tenant. Never allow data in one
            // tenant to be accessed from another tenant."
            //
            // References:
            // - https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation
            // - https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
            // ─────────────────────────────────────────────────────────────────
            try {
                AADSSO_AuthorizationHelper::validate_tenant_id($jwt, $this->settings);
            } catch (Throwable $e) {
                AADSSO_Logger::log_error('Tenant ID validation failed: ' . $e->getMessage());

                return new WP_Error(
                    'tenant_validation_failed',
                    \sprintf(
                        __('ERROR: Tenant ID validation failed. %s', 'aad-sso-wordpress'),
                        esc_html($e->getMessage())
                    )
                );
            }

            // Validate issuer claim to prevent token substitution attacks
            // Microsoft Entra ID v2.0 issuer patterns:
            // - Single tenant: https://login.microsoftonline.com/{tenant-id}/v2.0
            // - /common/ or /organizations/: templated as https://login.microsoftonline.com/{tenantid}/v2.0
            //   in metadata, but JWT contains concrete tenant ID
            $expected_issuer = $this->settings->issuer;
            if (!empty($expected_issuer)) {
                // Check if expected issuer is templated (contains {tenantid} placeholder)
                if (str_contains($expected_issuer, '{tenantid}')) {
                    // For /common/ or /organizations/ endpoints, validate JWT issuer matches the pattern
                    // but with a concrete tenant ID instead of {tenantid}
                    // Empty issuer must be rejected to prevent bypass
                    if (empty($jwt_iss)) {
                        AADSSO_Logger::log_error('JWT issuer claim is empty');

                        return new WP_Error(
                            'invalid_token_issuer',
                            __('ERROR: Token issuer is missing. This may indicate a token substitution attack.', 'aad-sso-wordpress')
                        );
                    }

                    // Convert templated issuer to regex pattern
                    // Template: https://login.microsoftonline.com/{tenantid}/v2.0
                    // Pattern: https://login\.microsoftonline\.com/[^/]+/v2\.0
                    $base = preg_quote('https://login.microsoftonline.com/', '#');
                    $pattern = '#^' . $base . '[^/]+/v2\.0$#';

                    if (!preg_match($pattern, $jwt_iss)) {
                        AADSSO_Logger::log_error(\sprintf(
                            'Issuer mismatch: expected pattern "%s", got "%s"',
                            $expected_issuer,
                            $jwt_iss
                        ));

                        return new WP_Error(
                            'invalid_token_issuer',
                            __('ERROR: Token issuer validation failed. This may indicate a token substitution attack.', 'aad-sso-wordpress')
                        );
                    }
                } else {
                    // For single-tenant deployments with concrete issuer: exact match required
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
                }
            } else {
                // Fallback validation if issuer not configured yet
                // Check that issuer follows Microsoft Entra ID v2.0 pattern
                // Allow optional trailing slash for flexibility
                // Empty issuer must be rejected to prevent bypass
                if (empty($jwt_iss)) {
                    AADSSO_Logger::log_error('JWT issuer claim is empty');

                    return new WP_Error(
                        'invalid_token_issuer',
                        __('ERROR: Token issuer is missing. This may indicate a token substitution attack.', 'aad-sso-wordpress')
                    );
                }

                $issuer_valid = preg_match(
                    '#^https://login\.microsoftonline\.com/[^/]+/v2\.0/?$#',
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

            // Regenerate session ID after successful authentication
            // This prevents session fixation attacks and clears PKCE verifier
            $this->regenerate_session();
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

        /** @var string */
        $oid_raw = $jwt->oid ?? '';
        $aad_oid = \is_string($oid_raw) ? $oid_raw : '';
        /** @var string */
        $tid_raw = $jwt->tid ?? '';
        $aad_tid = \is_string($tid_raw) ? $tid_raw : '';

        /** @var mixed */
        $log_preferred_username = $jwt->preferred_username ?? '(null)';
        /** @var mixed */
        $log_mail = $jwt->mail ?? '(null)';
        AADSSO_Logger::log_debug(\sprintf(
            'User claims: upn=%s, unique_name=%s, email=%s, preferred_username=%s, mail=%s, oid=%s, tid=%s',
            $upn ?? '(null)',
            $unique_name ?? '(null)',
            $jwt->email ?? '(null)',
            \is_string($log_preferred_username) ? $log_preferred_username : '(non-string)',
            \is_string($log_mail) ? $log_mail : '(non-string)',
            '' !== $aad_oid ? $aad_oid : '(null)',
            '' !== $aad_tid ? $aad_tid : '(null)'
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

        /** @var null|string */
        $email_claim = null;
        /** @var mixed */
        $email_raw = $jwt->email ?? null;
        if (\is_string($email_raw)) {
            $email_claim = $email_raw;
        }
        /** @var mixed */
        $preferred_username_raw = $jwt->preferred_username ?? null;
        if (null === $email_claim && \is_string($preferred_username_raw)) {
            $email_claim = $preferred_username_raw;
        }

        $user = null;

        if (mb_strlen($aad_oid) > 0 && true === $this->settings->use_immutable_user_linking) {
            $user = $this->find_user_by_aad_oid($aad_oid, $aad_tid);

            if ($user instanceof WP_User) {
                $stored_tid = get_user_meta($user->ID, 'aad_tid', true);

                if ('' === $stored_tid && '' !== $aad_tid) {
                    AADSSO_Logger::log_warning(\sprintf(
                        'Storing tenant ID for oid=%s: tid=%s (first match).',
                        $aad_oid,
                        $aad_tid
                    ));
                    update_user_meta($user->ID, 'aad_tid', $aad_tid);
                    $stored_tid = $aad_tid;
                }

                if ('' !== $stored_tid && '' !== $aad_tid && $stored_tid !== $aad_tid) {
                    AADSSO_Logger::log_warning(\sprintf(
                        'Tenant ID mismatch for oid=%s: stored=%s, token=%s.',
                        $aad_oid,
                        $stored_tid,
                        $aad_tid
                    ));

                    return new WP_Error(
                        'tenant_mismatch',
                        __(
                            'ERROR: Your account tenant does not match the stored tenant. '
                            . 'This may indicate a security issue. Please contact an administrator.',
                            'aad-sso-wordpress'
                        )
                    );
                }

                AADSSO_Logger::log_debug(\sprintf(
                    'Matched user by immutable oid [%s] to WordPress user [%s].',
                    $aad_oid,
                    (string) $user->ID
                ), 10);
            }
        }

        if (!($user instanceof WP_User) && !$this->settings->force_immutable_linking) {
            $user = $this->find_user_by_heuristics($email_claim, $unique_name, $upn);

            if ($user instanceof WP_User) {
                if (mb_strlen($aad_oid) > 0) {
                    update_user_meta($user->ID, 'aad_oid', $aad_oid);
                    update_user_meta($user->ID, 'aad_tid', $aad_tid);
                    AADSSO_Logger::log_debug(\sprintf(
                        'Migrated user [%s] to immutable linking with oid [%s].',
                        (string) $user->ID,
                        $aad_oid
                    ), 10);
                }

                AADSSO_Logger::log_debug(\sprintf(
                    'Matched user by heuristic fallback: [%s] to [%s].',
                    $unique_name,
                    (string) $user->ID
                ), 10);
            }
        }

        if ($user instanceof WP_User) {
            if (
                null !== $email_claim
                && mb_strtolower($user->user_email) !== mb_strtolower($email_claim)
            ) {
                AADSSO_Logger::log_warning(\sprintf(
                    'Email mismatch for user %d: WordPress has %s, Entra ID has %s.',
                    $user->ID,
                    $user->user_email,
                    $email_claim
                ), 10);
            }

            if (mb_strlen($aad_oid) > 0) {
                update_user_meta($user->ID, 'aad_oid', $aad_oid);
                update_user_meta($user->ID, 'aad_tid', $aad_tid);
            }
        } else {
            if (true === $this->settings->enable_auto_provisioning) {
                $provisioning_denied = false;
                $denial_reasons = [];

                if ($this->settings->require_tenant_restriction_for_provisioning) {
                    $tenant_mode = $this->settings->tenantRestrictionMode;
                    if ('none' === $tenant_mode) {
                        $provisioning_denied = true;
                        $denial_reasons[] = 'Tenant restriction is not enforced.';
                        AADSSO_Logger::log_warning('Auto-provisioning blocked: tenant restriction not enforced.');
                    } elseif ('single' === $tenant_mode) {
                        $expected_tid = $this->settings->expected_tenant_id;
                        if ('' !== $expected_tid && '' !== $aad_tid && $expected_tid !== $aad_tid) {
                            $provisioning_denied = true;
                            $denial_reasons[] = \sprintf('User tenant (%s) does not match expected tenant (%s).', $aad_tid, $expected_tid);
                        }
                    } elseif ('multi' === $tenant_mode) {
                        $allowed_tids = $this->settings->allowed_tenant_ids;
                        if (!empty($allowed_tids) && '' !== $aad_tid && !\in_array($aad_tid, $allowed_tids, true)) {
                            $provisioning_denied = true;
                            $denial_reasons[] = \sprintf('User tenant (%s) is not in the allowed tenants list.', $aad_tid);
                        }
                    }
                }

                if ($this->settings->require_role_policy_for_provisioning && !$provisioning_denied) {
                    $has_role_policy = false;

                    if (!empty($this->settings->default_wp_role)) {
                        $has_role_policy = true;
                    }

                    if (true === $this->settings->enable_aad_group_to_wp_role) {
                        $has_role_policy = true;
                    }

                    if (!$has_role_policy) {
                        $provisioning_denied = true;
                        $denial_reasons[] = 'No role assignment policy configured.';
                        AADSSO_Logger::log_warning('Auto-provisioning blocked: no role assignment policy configured.');
                    }
                }

                if ($provisioning_denied) {
                    return new WP_Error(
                        'auto_provisioning_policy_violation',
                        '<strong>Auto-provisioning is blocked for security.</strong><br />'
                        . 'Reasons: ' . esc_html(implode(' ', $denial_reasons)) . '<br />'
                        . 'Please contact your administrator.'
                    );
                }

                // Group membership check for role-mapped provisioning
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

                // Create the new user
                /** @var mixed */
                $given_name_raw = $jwt->given_name ?? '';
                $given_name = \is_string($given_name_raw) ? sanitize_text_field($given_name_raw) : '';
                /** @var mixed */
                $family_name_raw = $jwt->family_name ?? '';
                $family_name = \is_string($family_name_raw) ? sanitize_text_field($family_name_raw) : '';

                $user_email = null !== $email_claim ? sanitize_email($email_claim) : sanitize_email($unique_name);
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

                // Store aad_oid and aad_tid for immutable linking on newly provisioned users
                // This ensures future logins use the secure immutable method
                if (mb_strlen($aad_oid) > 0) {
                    update_user_meta($new_user_id, 'aad_oid', $aad_oid);
                    update_user_meta($new_user_id, 'aad_tid', $aad_tid);
                    AADSSO_Logger::log_debug(\sprintf(
                        'Stored immutable identifier for new user [%s]: oid=%s, tid=%s.',
                        (string) $new_user_id,
                        $aad_oid,
                        $aad_tid
                    ), 10);
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

        // Generate PKCE code_verifier (RFC 7636)
        // This is stored and sent during token exchange for security
        $code_verifier = aad_sso_generate_pkce_code_verifier();
        $_SESSION['aadsso_pkce_code_verifier'] = $code_verifier;

        return AADSSO_AuthorizationHelper::get_authorization_url($this->settings, $antiforgery_id, $code_verifier);
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
            // ─────────────────────────────────────────────────────────────────
            // Session security hardening - MUST be set BEFORE session_start()
            //
            // Per PHP security best practices:
            // - session.use_strict_mode: Reject uninitialized session IDs
            // - session.use_only_cookies: Prevent URL-based session IDs
            //
            // References:
            // - https://php.net/manual/en/features.session.security.ini.php
            // - https://paragonie.com/blog/2015/04/fast-track-safe-and-secure-php-sessions
            // ─────────────────────────────────────────────────────────────────

            // Enable strict session mode to reject uninitialized session IDs
            // This must be set BEFORE session_start() to take effect
            if ('0' === \ini_get('session.use_strict_mode')) {
                ini_set('session.use_strict_mode', '1');
            }

            // Force cookie-only sessions (no URL-based session IDs)
            // This must be set BEFORE session_start() to take effect
            if ('0' === \ini_get('session.use_only_cookies')) {
                ini_set('session.use_only_cookies', '1');
            }

            // Set hardened session cookie parameters BEFORE starting the session
            // Per PHP session security best practices:
            // - Secure: Only send cookie over HTTPS (use is_ssl() for dynamic detection)
            // - HttpOnly: Prevent JavaScript access to session cookie
            // - SameSite=Lax: Provides CSRF protection while allowing top-level navigation
            //
            // Note: Plugin requires PHP 8.5.5+, so PHP 7.3+ array signature is always available.
            //
            // References:
            // - https://php.net/manual/en/function.session-set-cookie-params.php
            // - https://paragonie.com/blog/2015/04/fast-track-safe-and-secure-php-sessions
            //
            // Use WordPress is_ssl() to detect HTTPS, with fallback for non-WordPress contexts
            $is_secure = false;
            if (\function_exists('is_ssl')) {
                $is_secure = (bool) is_ssl();
            } else {
                // Fallback: check if HTTPS is detected via server variables
                $is_secure = (
                    (!empty($_SERVER['HTTPS']) && 'off' !== mb_strtolower($_SERVER['HTTPS']))
                    || (!empty($_SERVER['SERVER_PORT']) && 443 === (int) $_SERVER['SERVER_PORT'])
                );
            }

            session_set_cookie_params([
                'lifetime' => 0,    // Session cookie (expires when browser closes)
                'path' => '/',
                'domain' => '',
                'secure' => $is_secure,   // Dynamic: HTTPS only when on SSL connection
                'httponly' => true, // No JavaScript access
                'samesite' => 'Lax',
            ]);

            // NOW start the session - all settings above will take effect
            session_start();
        }
    }

    /**
     * Regenerate session ID and clear sensitive auth-related session data.
     *
     * Per PHP session security best practices, session ID should be regenerated:
     * - After successful authentication (to prevent session fixation)
     * - After privilege level changes
     *
     * The true parameter requests deletion of the old session data.
     *
     * References:
     * - https://php.net/manual/en/function.session-regenerate-id.php
     * - https://paragonie.com/blog/2015/04/fast-track-safe-and-secure-php-sessions
     */
    public function regenerate_session(): void
    {
        if (session_id()) {
            // Regenerate session ID before clearing old session data
            // This prevents session fixation attacks
            session_regenerate_id(true);

            // Clear sensitive authentication-related session data
            // These values are no longer needed after successful authentication
            unset($_SESSION['aadsso_pkce_code_verifier']);

            AADSSO_Logger::log_debug('Session ID regenerated after successful authentication', 10);
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

    /**
     * @param string $oid
     * @param string $tid
     *
     * @return null|WP_User
     */
    private function find_user_by_aad_oid(string $oid, string $tid): ?WP_User
    {
        global $wpdb;

        /** @var string */
        $query = $wpdb->prepare(
            "SELECT user_id FROM {$wpdb->usermeta} "
            . "WHERE meta_key = 'aad_oid' AND meta_value = %s "
            . 'LIMIT 1',
            $oid
        );

        /** @var null|string */
        $user_id = $wpdb->get_var($query);

        if (null === $user_id || !is_numeric($user_id)) {
            return null;
        }

        $user = new WP_User((int) $user_id);

        return $user->exists() ? $user : null;
    }

    /**
     * @param null|string $email_claim
     * @param string      $unique_name
     * @param null|string $upn
     *
     * @return null|WP_User
     */
    private function find_user_by_heuristics(?string $email_claim, string $unique_name, ?string $upn): ?WP_User
    {
        $match_field = $this->settings->field_to_match_to_upn;
        $match_value = $unique_name;

        if ('email' === $match_field && null !== $email_claim) {
            $match_value = $email_claim;
        }

        $user = get_user_by($match_field, $match_value);

        if (!($user instanceof WP_User)
            && 'email' === $match_field
            && null !== $email_claim
            && $email_claim !== $match_value
        ) {
            $user = get_user_by('email', $email_claim);
        }

        if (true === $this->settings->match_on_upn_alias && !($user instanceof WP_User)) {
            $domain_hint = sanitize_text_field($this->settings->org_domain_hint);
            if (!empty($domain_hint)) {
                $suffix = '@' . $domain_hint;
                if (str_ends_with($unique_name, $suffix)) {
                    $username = mb_trim(mb_substr($unique_name, 0, -mb_strlen($suffix)));
                    if ('' !== $username) {
                        $user = get_user_by($this->settings->field_to_match_to_upn, $username);
                        if (!($user instanceof WP_User) && 'email' === $this->settings->field_to_match_to_upn) {
                            $user = get_user_by('email', mb_strtolower($username));
                        }
                    }
                }
            }
        }

        if (!($user instanceof WP_User) && 'email' === $match_field && null !== $email_claim) {
            $lowercased_email = mb_strtolower($email_claim);
            $lowercased_unique = mb_strtolower($unique_name);

            $user = get_user_by($match_field, $lowercased_email);
            if (!($user instanceof WP_User)) {
                $user = get_user_by($match_field, $lowercased_unique);
            }
        }

        return $user instanceof WP_User ? $user : null;
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
    /**
     * Generate a cryptographically secure UUID v4.
     *
     * @return string RFC 4122 compliant UUID v4
     */
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

/*
 * Register activation and deactivation hooks at plugin load time.
 *
 * These hooks must be registered before plugins_loaded runs, otherwise they
 * will never fire. WordPress requires activation/deactivation hooks to be
 * registered at plugin load time, not inside plugins_loaded callbacks.
 */
register_activation_hook(__FILE__, [AADSSO::class, 'activate']);
register_deactivation_hook(__FILE__, [AADSSO::class, 'deactivate']);

/*
 * Initialize the plugin on plugins_loaded hook.
 *
 * Deferred initialization ensures WordPress is fully loaded before:
 * - Loading settings from database
 * - Making HTTP requests for OpenID configuration
 * - Registering hooks and filters
 *
 * Priority 1 ensures this runs early enough for other plugins to interact.
 */
add_action('plugins_loaded', static function (): void {
    $aadsso_settings_instance = AADSSO_Settings::init();
    $aadsso = AADSSO::get_instance($aadsso_settings_instance);
    $aadsso->load_textdomain();
}, 1);
