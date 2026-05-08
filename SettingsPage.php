<?php

declare(strict_types=1);

class SettingsPage
{
    /**
     * @var array<string, mixed>
     */
    private array $settings = [];

    /**
     * @var false|string
     */
    private string|false $options_page_id = false;

    public function __construct()
    {
        add_action('admin_enqueue_scripts', [$this, 'maybe_include_jquery']);
        add_action('admin_menu', [$this, 'add_options_page']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_init', [$this, 'maybe_reset_settings']);
        add_action('admin_init', [$this, 'maybe_migrate_settings']);
        add_action('all_admin_notices', [$this, 'notify_if_reset_successful']);
        add_action('all_admin_notices', [$this, 'notify_json_migrate_status']);
        add_action('all_admin_notices', [$this, 'notify_openid_configuration_warning']);
        add_action('all_admin_notices', [$this, 'notify_upgrade_migration']);

        // Register AJAX handler for dismissing the migration notice
        // Must be registered here (not in notify_upgrade_migration) because all_admin_notices
        // hook is not executed during AJAX requests to admin-ajax.php
        add_action('wp_ajax_aadsso_dismiss_migration_notice', [$this, 'ajax_dismiss_migration_notice']);

        $default_settings = AADSSO_Settings::get_defaults();
        /** @var array<string, mixed> $defaultSettingsArr */
        $defaultSettingsArr = \is_array($default_settings) ? $default_settings : [];
        $saved_settings = get_option('aadsso_settings');
        /** @var array<string, mixed> $settings */
        $settings = \is_array($saved_settings) ? $saved_settings : [];
        $this->settings = $settings;
        foreach ($defaultSettingsArr as $key => $default_value) {
            if (!isset($this->settings[$key])) {
                $this->settings[$key] = $default_value;
            }
        }
    }

    /**
     * Display warning if OpenID configuration may not be optimal.
     */
    public function notify_openid_configuration_warning(): void
    {
        // Only show on our settings page
        $screen = get_current_screen();
        if (null === $screen || 'settings_page_aadsso_settings' !== $screen->id) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        $openid_endpoint = $this->settings['openid_configuration_endpoint'] ?? '';
        if (!\is_string($openid_endpoint) || empty($openid_endpoint)) {
            return;
        }

        // Warn if using /common/ endpoint (multi-tenant)
        if (str_contains($openid_endpoint, '/common/.well-known/openid-configuration')) {
            echo '<div class="notice notice-warning">';
            echo '<p>';
            echo wp_kses_post(
                __(
                    '<strong>Microsoft Entra ID SSO:</strong> You are using the multi-tenant endpoint '
                    . '(<code>/common/</code>), which allows users from any Microsoft Entra ID organization '
                    . 'to sign in. For single-tenant deployments (recommended for most organizations), '
                    . 'use your tenant-specific endpoint: '
                    . '<code>https://login.microsoftonline.com/{your-tenant-id}/.well-known/openid-configuration</code>.',
                    'aad-sso-wordpress'
                )
            );
            echo '</p></div>';
        }
    }

    /**
     * Display migration notice for users upgrading from older versions.
     * Specifically for the /common/ → /organizations/ endpoint change.
     *
     * @see https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration
     *      accepts personal Microsoft accounts (MSA)
     * @see https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration
     *      only accepts work/school accounts (no MSA)
     */
    public function notify_upgrade_migration(): void
    {
        // Only show on our settings page
        $screen = get_current_screen();
        if (null === $screen || 'settings_page_aadsso_settings' !== $screen->id) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        // Only show once (dismissed via user meta)
        $dismissed = get_user_meta(get_current_user_id(), 'aadsso_migration_notice_dismissed', true);
        if ($dismissed) {
            return;
        }

        // Check if this appears to be an existing install (not using default endpoint)
        // or if they explicitly set /common/ before
        $openid_endpoint = $this->settings['openid_configuration_endpoint'] ?? '';
        if (!\is_string($openid_endpoint)) {
            return;
        }

        // Only show for /organizations/ users who might need MSA support
        if (!str_contains($openid_endpoint, '/organizations/.well-known/openid-configuration')) {
            return;
        }

        // Check if they had /common/ before (stored in migration flag option)
        $previous_endpoint = get_option('aadsso_previous_openid_endpoint', '');
        $is_upgrade_from_common = (
            '' !== $previous_endpoint
            && str_contains($previous_endpoint, '/common/.well-known/openid-configuration')
        );

        // Also show for sites that were active before this change (no stored version = old install)
        $stored_version = get_option('aadsso_version', null);
        $no_version_stored = (null === $stored_version);

        if (!$is_upgrade_from_common && !$no_version_stored) {
            return;
        }

        echo '<div class="notice notice-warning is-dismissible" id="aadsso-migration-notice">';
        echo '<p>';
        echo wp_kses_post(
            __(
                '<strong>Microsoft Entra ID SSO - Important Update:</strong> This plugin now defaults to the '
                . '<code>/organizations/</code> endpoint, which only accepts work or school accounts (Microsoft Entra ID). '
                . 'If you need to support personal Microsoft accounts (consumer MSA), change the OpenID endpoint to: '
                . '<code>https://login.microsoftonline.com/common/.well-known/openid-configuration</code>',
                'aad-sso-wordpress'
            )
        );
        echo '</p>';
        echo '<p>';
        echo '<button type="button" class="button" onclick="'
            . "jQuery.post(ajaxurl, {action: 'aadsso_dismiss_migration_notice', nonce: '" . wp_create_nonce('aadsso_dismiss_migration') . "'}, function() { jQuery('#aadsso-migration-notice').fadeOut(); });"
            . '">' . esc_html__('Dismiss', 'aad-sso-wordpress') . '</button>';
        echo ' <a href="#" class="button button-secondary" onclick="jQuery(\'#openid_configuration_endpoint\').val(\''
            . esc_url(AADSSO_Settings::DEFAULT_OPENID_CONFIGURATION_ENDPOINT)
            . '\'); jQuery(\'#submit\').click(); return false;">' . esc_html__('Keep current endpoint', 'aad-sso-wordpress') . '</a>';
        echo ' <a href="#" class="button button-primary" onclick="jQuery(\'#openid_configuration_endpoint\').val(\'https://login.microsoftonline.com/common/.well-known/openid-configuration\'); jQuery(\'#submit\').click(); return false;">' . esc_html__('Switch to /common/ (supports MSA)', 'aad-sso-wordpress') . '</a>';
        echo '</p></div>';
    }

    /**
     * AJAX handler to dismiss the upgrade migration notice.
     */
    public function ajax_dismiss_migration_notice(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized', 403);
        }

        check_ajax_referer('aadsso_dismiss_migration', 'nonce');

        update_user_meta(get_current_user_id(), 'aadsso_migration_notice_dismissed', true);

        // Store that we've shown this notice so it doesn't reappear
        update_option('aadsso_migration_notice_shown', true);

        wp_die('OK');
    }

    public function maybe_reset_settings(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (!isset($_GET['aadsso_nonce'])) {
            return;
        }

        $nonce_raw = $_GET['aadsso_nonce'] ?? '';
        $nonce = \is_string($nonce_raw) ? sanitize_text_field(wp_unslash($nonce_raw)) : '';
        if (!wp_verify_nonce($nonce, 'aadsso_reset_settings')) {
            wp_safe_redirect(add_query_arg('aadsso_reset', 'failed', admin_url('options-general.php?page=aadsso_settings')));
            exit;
        }

        delete_option('aadsso_settings');
        wp_safe_redirect(add_query_arg('aadsso_reset', 'success', admin_url('options-general.php?page=aadsso_settings')));
        exit;
    }

    public function maybe_migrate_settings(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $nonce_raw = $_GET['aadsso_nonce'] ?? '';
        $nonce = \is_string($nonce_raw) ? sanitize_text_field(wp_unslash($nonce_raw)) : '';
        if ('' === $nonce
            || !wp_verify_nonce($nonce, 'aadsso_migrate_from_json')
            || !\defined('AADSSO_SETTINGS_PATH')
            || !\is_string(AADSSO_SETTINGS_PATH)
            || !file_exists(AADSSO_SETTINGS_PATH)
        ) {
            return;
        }

        $settings_file_path = AADSSO_SETTINGS_PATH;
        $json_content = file_get_contents($settings_file_path);
        if (false === $json_content) {
            wp_safe_redirect(add_query_arg(
                'aadsso_migrate_from_json_status',
                'invalid_json',
                admin_url('options-general.php?page=aadsso_settings')
            ));
            exit;
        }

        $legacy_settings = json_decode($json_content, true);
        $json_error = json_last_error();
        if (null === $legacy_settings && \JSON_ERROR_NONE !== $json_error) {
            AADSSO_Logger::log_error('JSON decode error during migration: ' . json_last_error_msg());
            wp_safe_redirect(add_query_arg(
                'aadsso_migrate_from_json_status',
                'invalid_json',
                admin_url('options-general.php?page=aadsso_settings')
            ));
            exit;
        }

        if (\is_array($legacy_settings) && isset($legacy_settings['aad_group_to_wp_role_map']) && \is_array($legacy_settings['aad_group_to_wp_role_map'])) {
            // aad_group_to_wp_role_map[group_id] = role_slug - convert to role_map format for UI compatibility
            $legacy_settings['role_map'] = [];
            foreach ($legacy_settings['aad_group_to_wp_role_map'] as $group_id => $role_slug) {
                $role_slug_sanitized = \is_string($role_slug) ? sanitize_text_field($role_slug) : '';
                $group_id_sanitized = \is_string($group_id) ? sanitize_text_field($group_id) : '';
                if (empty($role_slug_sanitized) || empty($group_id_sanitized)) {
                    continue;
                }
                // Store as role_slug => array of group_ids (matching UI format)
                if (!isset($legacy_settings['role_map'][$role_slug_sanitized])) {
                    $legacy_settings['role_map'][$role_slug_sanitized] = [$group_id_sanitized];
                } else {
                    $legacy_settings['role_map'][$role_slug_sanitized][] = $group_id_sanitized;
                }
            }
        }

        $sanitized_settings = $this->sanitize_settings($legacy_settings);
        update_option('aadsso_settings', $sanitized_settings);

        $dirname = \dirname($settings_file_path);
        $can_delete = is_writable($settings_file_path) && '' !== $dirname && is_writable($dirname);
        if ($can_delete) {
            unlink($settings_file_path);
            wp_safe_redirect(add_query_arg(
                'aadsso_migrate_from_json_status',
                'success',
                admin_url('options-general.php?page=aadsso_settings')
            ));
        } else {
            wp_safe_redirect(add_query_arg(
                'aadsso_migrate_from_json_status',
                'manual',
                admin_url('options-general.php?page=aadsso_settings')
            ));
        }
        exit;
    }

    public function notify_json_migrate_status(): void
    {
        if (!isset($_GET['aadsso_migrate_from_json_status'])) {
            return;
        }

        $status_raw = $_GET['aadsso_migrate_from_json_status'] ?? '';
        $status = \is_string($status_raw) ? sanitize_text_field(wp_unslash($status_raw)) : '';

        if ('success' === $status) {
            echo '<div id="message" class="notice notice-success"><p>'
                . esc_html__(
                    'Legacy settings have been migrated and the old configuration file has been deleted.',
                    'aad-sso-wordpress'
                )
                . ' ' . esc_html__(
                    'To finish migration, unset AADSSO_SETTINGS_PATH from wp-config.php.',
                    'aad-sso-wordpress'
                ) . '</p></div>';
        } elseif ('manual' === $status) {
            $settings_path = \defined('AADSSO_SETTINGS_PATH') && \is_string(AADSSO_SETTINGS_PATH) ? AADSSO_SETTINGS_PATH : '';
            echo '<div id="message" class="notice notice-warning"><p>'
                . esc_html__('Legacy settings have been migrated successfully.', 'aad-sso-wordpress') . ' '
                . \sprintf(esc_html__(
                    'To finish migration, delete the file at the path %s.',
                    'aad-sso-wordpress'
                ), '<code>' . esc_html($settings_path) . '</code>')
                . ' ' . \sprintf(
                    esc_html__('Then, unset %s from %s.', 'aad-sso-wordpress'),
                    '<code>AADSSO_SETTINGS_PATH</code>',
                    '<code>wp-config.php</code>'
                ) . '</p></div>';
        } elseif ('invalid_json' === $status) {
            $settings_path = \defined('AADSSO_SETTINGS_PATH') && \is_string(AADSSO_SETTINGS_PATH) ? AADSSO_SETTINGS_PATH : '';
            echo '<div id="message" class="notice notice-error"><p>'
                . \sprintf(
                    esc_html__('Legacy settings could not be migrated from %s.', 'aad-sso-wordpress'),
                    '<code>' . esc_html($settings_path) . '</code>'
                )
                . ' ' . esc_html__(
                    'File could not be parsed as JSON. Delete the file, or check its syntax.',
                    'aad-sso-wordpress'
                ) . '</p></div>';
        }
    }

    public function notify_if_reset_successful(): void
    {
        if (!isset($_GET['aadsso_reset'])) {
            return;
        }

        $status_raw = $_GET['aadsso_reset'] ?? '';
        $status = \is_string($status_raw) ? sanitize_text_field(wp_unslash($status_raw)) : '';

        if ('success' === $status) {
            echo '<div id="message" class="notice notice-warning"><p>'
                . esc_html__(
                    'Single Sign-on with Microsoft Entra ID settings have been reset to default.',
                    'aad-sso-wordpress'
                ) . '</p></div>';
        } elseif ('failed' === $status) {
            echo '<div id="message" class="notice notice-error"><p>'
                . esc_html__(
                    'Single Sign-on with Microsoft Entra ID settings reset failed. Invalid nonce.',
                    'aad-sso-wordpress'
                ) . '</p></div>';
        }
    }

    public function add_options_page(): void
    {
        $page_id = add_options_page(
            esc_html__('Microsoft Entra ID Settings', 'aad-sso-wordpress'),
            esc_html__('Microsoft Entra ID', 'aad-sso-wordpress'),
            'manage_options',
            'aadsso_settings',
            [$this, 'render_admin_page']
        );
        $this->options_page_id = $page_id;
    }

    public function render_admin_page(): void
    {
        require_once __DIR__ . '/view/settings.php';
    }

    public function register_settings(): void
    {
        register_setting(
            'aadsso_settings',
            'aadsso_settings',
            [$this, 'sanitize_settings']
        );

        add_settings_section(
            'aadsso_settings_general',
            esc_html__('General', 'aad-sso-wordpress'),
            [$this, 'settings_general_info'],
            'aadsso_settings_page'
        );

        add_settings_section(
            'aadsso_settings_advanced',
            esc_html__('Advanced', 'aad-sso-wordpress'),
            [$this, 'settings_advanced_info'],
            'aadsso_settings_page'
        );

        add_settings_field(
            'org_display_name',
            esc_html__('Display name', 'aad-sso-wordpress'),
            [$this, 'org_display_name_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'org_domain_hint',
            esc_html__('Domain hint', 'aad-sso-wordpress'),
            [$this, 'org_domain_hint_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'client_id',
            esc_html__('Client ID', 'aad-sso-wordpress'),
            [$this, 'client_id_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'client_secret',
            esc_html__('Client secret', 'aad-sso-wordpress'),
            [$this, 'client_secret_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'redirect_uri',
            esc_html__('Redirect URL', 'aad-sso-wordpress'),
            [$this, 'redirect_uri_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'logout_redirect_uri',
            esc_html__('Logout redirect URL', 'aad-sso-wordpress'),
            [$this, 'logout_redirect_uri_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'enable_full_logout',
            esc_html__('Enable full logout', 'aad-sso-wordpress'),
            [$this, 'enable_full_logout_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'field_to_match_to_upn',
            esc_html__('Field to match to UPN', 'aad-sso-wordpress'),
            [$this, 'field_to_match_to_upn_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'match_on_upn_alias',
            esc_html__('Match on alias of the UPN', 'aad-sso-wordpress'),
            [$this, 'match_on_upn_alias_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'enable_auto_provisioning',
            esc_html__('Enable auto-provisioning', 'aad-sso-wordpress'),
            [$this, 'enable_auto_provisioning_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'enable_auto_forward_to_aad',
            esc_html__('Enable auto-forward to Microsoft Entra ID', 'aad-sso-wordpress'),
            [$this, 'enable_auto_forward_to_aad_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'enable_aad_group_to_wp_role',
            esc_html__('Enable Microsoft Entra ID group to WordPress role association', 'aad-sso-wordpress'),
            [$this, 'enable_aad_group_to_wp_role_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'default_wp_role',
            esc_html__('Default WordPress role if not in Microsoft Entra ID group', 'aad-sso-wordpress'),
            [$this, 'default_wp_role_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'role_map',
            esc_html__('WordPress role to Microsoft Entra ID group map', 'aad-sso-wordpress'),
            [$this, 'role_map_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'openid_configuration_endpoint',
            esc_html__('OpenID Connect configuration endpoint', 'aad-sso-wordpress'),
            [$this, 'openid_configuration_endpoint_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'custom_scope',
            esc_html__('Custom OAuth scopes', 'aad-sso-wordpress'),
            [$this, 'custom_scope_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'aadsso_settings_security_info',
            esc_html__('Security Information', 'aad-sso-wordpress'),
            [$this, 'security_info_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );
    }

    public function security_info_callback(): void
    {
        echo '<p>' . esc_html__(
            'This plugin implements the following security measures:',
            'aad-sso-wordpress'
        ) . '</p>';
        echo '<ul>';
        echo '<li>' . esc_html__('CSRF protection via WordPress nonces', 'aad-sso-wordpress') . '</li>';
        echo '<li>' . esc_html__('XSS prevention via output escaping', 'aad-sso-wordpress') . '</li>';
        echo '<li>' . esc_html__('SQL injection prevention via WordPress prepared statements', 'aad-sso-wordpress') . '</li>';
        echo '<li>' . esc_html__('JWT signature verification using RS256', 'aad-sso-wordpress') . '</li>';
        echo '<li>' . esc_html__('Nonce verification for state parameter in OAuth flow', 'aad-sso-wordpress') . '</li>';
        echo '<li>' . esc_html__('Secure session management', 'aad-sso-wordpress') . '</li>';
        echo '<li>' . esc_html__('TLS/SSL verification for all external requests', 'aad-sso-wordpress') . '</li>';
        echo '</ul>';
    }

    /**
     * @param mixed $input
     *
     * @return array<string, mixed>
     */
    public function sanitize_settings(mixed $input): array
    {
        if (!\is_array($input)) {
            // Return current settings to prevent data loss
            // @var array<string, mixed>
            return get_option('aadsso_settings', []);
        }
        /** @var array<string, mixed> $input */
        $sanitized = [];

        $org_display_name_raw = $input['org_display_name'] ?? '';
        $sanitized['org_display_name'] = \is_string($org_display_name_raw) ? sanitize_text_field($org_display_name_raw) : '';

        $org_domain_hint_raw = $input['org_domain_hint'] ?? '';
        $sanitized['org_domain_hint'] = \is_string($org_domain_hint_raw) ? sanitize_text_field($org_domain_hint_raw) : '';

        $client_id_raw = $input['client_id'] ?? '';
        $sanitized['client_id'] = \is_string($client_id_raw) ? sanitize_text_field($client_id_raw) : '';

        $client_secret_raw = $input['client_secret'] ?? '';
        $sanitized['client_secret'] = \is_string($client_secret_raw) ? sanitize_text_field($client_secret_raw) : '';

        $redirect_uri_raw = $input['redirect_uri'] ?? '';
        $sanitized['redirect_uri'] = \is_string($redirect_uri_raw) ? esc_url_raw($redirect_uri_raw) : '';

        $logout_redirect_uri_raw = $input['logout_redirect_uri'] ?? '';
        $sanitized['logout_redirect_uri'] = \is_string($logout_redirect_uri_raw) ? esc_url_raw($logout_redirect_uri_raw) : '';

        $sanitized['enable_full_logout'] = !empty($input['enable_full_logout']);

        $field_to_match_raw = $input['field_to_match_to_upn'] ?? '';
        $sanitized['field_to_match_to_upn'] = \in_array($field_to_match_raw, ['login', 'email'], true)
            ? $field_to_match_raw
            : 'email';
        $sanitized['match_on_upn_alias'] = !empty($input['match_on_upn_alias']);
        $sanitized['enable_auto_provisioning'] = !empty($input['enable_auto_provisioning']);
        $sanitized['enable_auto_forward_to_aad'] = !empty($input['enable_auto_forward_to_aad']);
        $sanitized['enable_aad_group_to_wp_role'] = !empty($input['enable_aad_group_to_wp_role']);

        $default_wp_role_raw = $input['default_wp_role'] ?? '';
        $default_wp_role = \is_string($default_wp_role_raw) ? sanitize_text_field($default_wp_role_raw) : '';
        $valid_roles = array_keys($this->get_editable_roles());
        $sanitized['default_wp_role'] = \in_array($default_wp_role, $valid_roles, true) ? $default_wp_role : '';

        $openid_endpoint_raw = $input['openid_configuration_endpoint'] ?? AADSSO_Settings::DEFAULT_OPENID_CONFIGURATION_ENDPOINT;
        $sanitized['openid_configuration_endpoint'] = \is_string($openid_endpoint_raw) ? esc_url_raw($openid_endpoint_raw) : AADSSO_Settings::DEFAULT_OPENID_CONFIGURATION_ENDPOINT;

        $auth_endpoint_raw = $input['authorization_endpoint'] ?? '';
        $sanitized['authorization_endpoint'] = \is_string($auth_endpoint_raw) ? esc_url_raw($auth_endpoint_raw) : '';

        $token_endpoint_raw = $input['token_endpoint'] ?? '';
        $sanitized['token_endpoint'] = \is_string($token_endpoint_raw) ? esc_url_raw($token_endpoint_raw) : '';

        $jwks_uri_raw = $input['jwks_uri'] ?? '';
        $sanitized['jwks_uri'] = \is_string($jwks_uri_raw) ? esc_url_raw($jwks_uri_raw) : '';

        $end_session_raw = $input['end_session_endpoint'] ?? '';
        $sanitized['end_session_endpoint'] = \is_string($end_session_raw) ? esc_url_raw($end_session_raw) : '';

        $graph_endpoint_raw = $input['graph_endpoint'] ?? 'https://graph.microsoft.com';
        $sanitized['graph_endpoint'] = \is_string($graph_endpoint_raw) ? esc_url_raw($graph_endpoint_raw) : 'https://graph.microsoft.com';

        $graph_version_raw = $input['graph_version'] ?? '';
        $sanitized['graph_version'] = \in_array($graph_version_raw, ['v1.0', 'beta'], true)
            ? $graph_version_raw
            : 'v1.0';

        $custom_scope_raw = $input['custom_scope'] ?? '';
        $sanitized['custom_scope'] = \is_string($custom_scope_raw) ? sanitize_text_field($custom_scope_raw) : '';

        if (!empty($input['role_map']) && \is_array($input['role_map'])) {
            $sanitized_role_map = [];
            $valid_roles = array_keys($this->get_editable_roles());
            foreach ($input['role_map'] as $role => $groups) {
                $role_sanitized = \is_string($role) ? sanitize_text_field($role) : '';
                $groups = \is_array($groups) ? $groups : (\is_string($groups) ? explode(',', $groups) : []);
                if (!empty($role_sanitized) && \in_array($role_sanitized, $valid_roles, true)) {
                    $group_ids = [];
                    foreach ($groups as $group_id) {
                        $group_id_sanitized = \is_string($group_id) ? sanitize_text_field(mb_trim($group_id)) : '';
                        if (!empty($group_id_sanitized)) {
                            $group_ids[] = $group_id_sanitized;
                        }
                    }
                    if (!empty($group_ids)) {
                        $sanitized_role_map[$role_sanitized] = $group_ids;
                    }
                }
            }
            $sanitized['role_map'] = $sanitized_role_map;
        }

        return $sanitized;
    }

    public function settings_general_info(): void
    {
        echo '<p>' . esc_html__(
            'Configure the basic settings for Microsoft Entra ID single sign-on.',
            'aad-sso-wordpress'
        ) . '</p>';
    }

    public function settings_advanced_info(): void
    {
        echo '<p>' . esc_html__(
            'Configure advanced settings for Microsoft Entra ID single sign-on.',
            'aad-sso-wordpress'
        ) . '</p>';
    }

    public function org_display_name_callback(): void
    {
        $this->render_text_field('org_display_name');
        echo '<p class="description">' . esc_html__(
            'Display Name will be shown on the WordPress login screen.',
            'aad-sso-wordpress'
        ) . '</p>';
    }

    public function org_domain_hint_callback(): void
    {
        $this->render_text_field('org_domain_hint');
        echo '<p class="description">' . esc_html__(
            'Provides a hint to Microsoft Entra ID about the domain or tenant they will be logging '
            . 'in to. If the domain is federated, the user will be automatically redirected '
            . 'to federation endpoint.',
            'aad-sso-wordpress'
        ) . '</p>';
    }

    public function client_id_callback(): void
    {
        $this->render_text_field('client_id');
        echo '<p class="description">' . esc_html__(
            'The client ID of the Microsoft Entra ID application representing this blog.',
            'aad-sso-wordpress'
        ) . '</p>';
    }

    public function client_secret_callback(): void
    {
        /** @var string */
        $clientSecret = \is_string($this->settings['client_secret'] ?? null) ? $this->settings['client_secret'] : '';
        $value = esc_attr($clientSecret);
        printf(
            '<input class="regular-text" type="password" autocomplete="new-password" '
            . 'name="aadsso_settings[client_secret]" id="client_secret" value="%s" />',
            $value
        );
        echo '<p class="description">' . esc_html__(
            'A secret key for the Microsoft Entra ID application representing this blog.',
            'aad-sso-wordpress'
        ) . '</p>';
    }

    public function redirect_uri_callback(): void
    {
        $this->render_text_field('redirect_uri');
        echo ' <a href="#" class="button button-secondary" onclick="jQuery(\'#redirect_uri\').val(\''
            . esc_url(wp_login_url()) . '\'); return false;">' . esc_html__('Set default', 'aad-sso-wordpress')
            . '</a>';
        echo '<p class="description">' . esc_html__(
            'The URL where the user is redirected to after authenticating with Microsoft Entra ID. '
            . 'This URL must be registered in Microsoft Entra ID as a valid redirect URL, and it must '
            . 'be a page that invokes the "authenticate" filter. If you don\'t know what '
            . 'to set, leave the default value (which is this blog\'s login page).',
            'aad-sso-wordpress'
        ) . '</p>';
    }

    public function logout_redirect_uri_callback(): void
    {
        $this->render_text_field('logout_redirect_uri');
        echo ' <a href="#" class="button button-secondary" onclick="jQuery(\'#logout_redirect_uri\').val(\''
            . esc_url(wp_login_url()) . '\'); return false;">' . esc_html__('Set default', 'aad-sso-wordpress')
            . '</a>';
        echo '<p class="description">' . esc_html__(
            'The URL where the user is redirected to after signing out of Microsoft Entra ID. This '
            . 'URL must be registered in Microsoft Entra ID as a valid redirect URL. (This does not '
            . 'affect logging out of the blog, it is only used when logging out of Microsoft Entra ID.)',
            'aad-sso-wordpress'
        ) . '</p>';
    }

    public function field_to_match_to_upn_callback(): void
    {
        $selected = $this->settings['field_to_match_to_upn'] ?? 'email';
        ?>
        <select name="aadsso_settings[field_to_match_to_upn]" id="field_to_match_to_upn">
            <option value="email"<?php selected($selected, 'email'); ?>>
                <?php echo esc_html__('Email Address', 'aad-sso-wordpress'); ?>
            </option>
            <option value="login"<?php selected($selected, 'login'); ?>>
                <?php echo esc_html__('Login Name', 'aad-sso-wordpress'); ?>
            </option>
        </select>
        <?php
        echo '<p class="description">' . esc_html__(
            'This specifies the WordPress user field which will be used to match to the '
            . 'Microsoft Entra ID user\'s UserPrincipalName.',
            'aad-sso-wordpress'
        ) . '</p>';
    }

    public function match_on_upn_alias_callback(): void
    {
        $this->render_checkbox_field(
            'match_on_upn_alias',
            wp_kses_post(
                __(
                    'Match WordPress users based on the alias of their Microsoft Entra ID '
                    . 'UserPrincipalName. For example, Microsoft Entra ID username <code>bob@example.com</code> '
                    . 'will match WordPress user <code>bob</code>.',
                    'aad-sso-wordpress'
                )
            )
        );
    }

    public function enable_auto_provisioning_callback(): void
    {
        $this->render_checkbox_field(
            'enable_auto_provisioning',
            esc_html__(
                'Automatically create WordPress users, if needed, for authenticated Microsoft Entra ID users.',
                'aad-sso-wordpress'
            )
        );
    }

    public function enable_auto_forward_to_aad_callback(): void
    {
        $this->render_checkbox_field(
            'enable_auto_forward_to_aad',
            esc_html__(
                'Automatically forward users to the Microsoft Entra ID to sign in, skipping the '
                . 'WordPress login screen.',
                'aad-sso-wordpress'
            )
        );
    }

    public function enable_aad_group_to_wp_role_callback(): void
    {
        $this->render_checkbox_field(
            'enable_aad_group_to_wp_role',
            esc_html__(
                'Automatically assign WordPress user roles based on Microsoft Entra ID group membership.',
                'aad-sso-wordpress'
            )
        );
    }

    public function enable_full_logout_callback(): void
    {
        $this->render_checkbox_field(
            'enable_full_logout',
            esc_html__(
                'Do a full logout of Microsoft Entra ID when logging out of WordPress.',
                'aad-sso-wordpress'
            )
        );
    }

    public function default_wp_role_callback(): void
    {
        if (!isset($this->settings['default_wp_role'])) {
            $this->settings['default_wp_role'] = '';
        }

        echo '<select name="aadsso_settings[default_wp_role]" id="default_wp_role">';
        printf('<option value="">%s</option>', esc_html__('(None, deny access)', 'aad-sso-wordpress'));
        foreach ($this->get_editable_roles() as $role_slug => $role) {
            $role_name = \is_array($role) && isset($role['name']) && \is_string($role['name']) ? $role['name'] : '';
            printf(
                '<option value="%s"%s>%s</option>',
                esc_attr($role_slug),
                selected($this->settings['default_wp_role'] ?? '', $role_slug, false),
                esc_html($role_name)
            );
        }
        echo '</select>';
        echo '<p class="description">' . esc_html__(
            'This is the default role that users will be assigned to if matching Microsoft Entra ID '
            . 'group to WordPress roles is enabled, but the signed in user isn\'t a member of any of the '
            . 'configured Microsoft Entra ID groups.',
            'aad-sso-wordpress'
        ) . '</p>';
    }

    public function role_map_callback(): void
    {
        echo '<p>' . esc_html__('Map WordPress roles to Microsoft Entra ID groups.', 'aad-sso-wordpress') . '</p>';
        echo '<table class="widefat" id="aadsso_role_map">';
        echo '<thead><tr>';
        echo '<th>' . esc_html__('WordPress Role', 'aad-sso-wordpress') . '</th>';
        echo '<th>' . esc_html__('Microsoft Entra ID Group Object ID', 'aad-sso-wordpress') . '</th>';
        echo '<th></th>';
        echo '</tr></thead><tbody>';

        $role_map = isset($this->settings['role_map']) && \is_array($this->settings['role_map'])
            ? $this->settings['role_map']
            : [];
        $roles = $this->get_editable_roles();
        $row_index = 0;

        foreach ($roles as $role_slug => $role) {
            $group_ids = isset($role_map[$role_slug]) && \is_string($role_map[$role_slug])
                ? $role_map[$role_slug]
                : '';
            $role_name = \is_array($role) && isset($role['name']) && \is_string($role['name']) ? $role['name'] : '';
            echo '<tr class="role_map_row">';
            echo '<td>' . esc_html($role_name) . '</td>';
            echo '<td><input type="text" class="regular-text" name="aadsso_settings[role_map]['
                . esc_attr($role_slug) . ']" value="' . esc_attr($group_ids) . '" /></td>';
            echo '<td><span class="description">'
                . esc_html__('Enter comma-separated group Object IDs', 'aad-sso-wordpress') . '</span></td>';
            echo '</tr>';
            ++$row_index;
        }

        echo '</tbody></table>';
    }

    public function openid_configuration_endpoint_callback(): void
    {
        $this->render_text_field('openid_configuration_endpoint');
        $default_endpoint = AADSSO_Settings::get_defaults('openid_configuration_endpoint');
        $default_url = \is_string($default_endpoint) ? $default_endpoint : AADSSO_Settings::DEFAULT_OPENID_CONFIGURATION_ENDPOINT;
        echo ' <a href="#" class="button button-secondary" onclick="jQuery(\'#openid_configuration_endpoint\').val(\''
            . esc_url($default_url)
            . '\'); return false;">' . esc_html__('Set default', 'aad-sso-wordpress') . '</a>';
        echo '<p class="description">' . wp_kses_post(
            __(
                'The OpenID Connect configuration endpoint for Microsoft Entra ID. '
                . 'For single-tenant deployments (recommended for most organizations), use: '
                . '<code>https://login.microsoftonline.com/{tenant-id}/.well-known/openid-configuration</code>, '
                . 'where <code>{tenant-id}</code> is your tenant ID or verified domain. '
                . 'For multi-tenant applications supporting users from any organization, use: '
                . '<code>https://login.microsoftonline.com/common/.well-known/openid-configuration</code>. '
                . 'The default <code>/organizations/</code> endpoint supports work and school accounts.',
                'aad-sso-wordpress'
            )
        ) . '</p>';
    }

    public function custom_scope_callback(): void
    {
        $this->render_text_field('custom_scope');
        echo '<p class="description">' . wp_kses_post(
            __(
                'Add additional OAuth 2.0 scopes beyond the defaults. By default, the plugin requests: '
                . '<code>openid email profile offline_access</code>. When group-based role mapping is '
                . 'enabled, it also requests: <code>https://graph.microsoft.com/User.Read</code> and '
                . '<code>https://graph.microsoft.com/GroupMember.Read.All</code>. Enter additional scopes '
                . 'separated by spaces (e.g., <code>Calendars.Read User.ReadBasic.All</code>).',
                'aad-sso-wordpress'
            )
        ) . '</p>';
    }

    public function render_text_field(string $name): void
    {
        $value = isset($this->settings[$name]) && \is_string($this->settings[$name])
            ? esc_attr($this->settings[$name])
            : '';
        printf(
            '<input class="regular-text" type="text" '
            . 'name="aadsso_settings[%1$s]" id="%1$s" value="%2$s" />',
            esc_attr($name),
            $value
        );
    }

    public function render_checkbox_field(string $name, string $label): void
    {
        printf(
            '<input type="checkbox" name="aadsso_settings[%1$s]" id="%1$s" value="1"%2$s />'
            . '<label for="%1$s">%3$s</label>',
            esc_attr($name),
            checked(!empty($this->settings[$name]), true, false),
            $label
        );
    }

    public function is_on_options_page(): bool
    {
        $screen = get_current_screen();
        if (null === $screen || false === $this->options_page_id) {
            return false;
        }

        return $screen->id === (string) $this->options_page_id;
    }

    public function maybe_include_jquery(): void
    {
        if ($this->is_on_options_page()) {
            wp_enqueue_script('jquery');
        }
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function get_editable_roles(): array
    {
        if (!\function_exists('wp_roles')) {
            global $wp_roles;

            // Defensive check - $wp_roles is WP_Roles object in WordPress context
            if (!isset($wp_roles) || !\is_object($wp_roles)) {
                // @var array<string, array<string, mixed>>
                return [];
            }

            /** @var array<string, array<string, mixed>> $roles */
            $roles = $wp_roles->roles ?? [];

            return \is_array($roles) ? $roles : [];
        }

        $roles_obj = wp_roles();

        // Defensive check - wp_roles() returns WP_Roles object
        if (!\is_object($roles_obj)) {
            // @var array<string, array<string, mixed>>
            return [];
        }

        /** @var array<string, array<string, mixed>> $roles */
        $roles = $roles_obj->roles ?? [];

        return \is_array($roles) ? $roles : [];
    }
}

class_alias(SettingsPage::class, 'AADSSO_Settings_Page');
