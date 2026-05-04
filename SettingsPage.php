<?php

/**
 * Settings page class for Microsoft Entra ID SSO plugin.
 *
 * Handles the WordPress admin settings page rendering and validation.
 *
 
 */
declare(strict_types=1);

/**
 * Settings page class.
 */
class AADSSO_Settings_Page
{
    /** @var array<string, mixed> Plugin settings */
    private array $settings = [];

    /** @var int|false Options page ID */
    private int|false $options_page_id = false;

    public function __construct()
    {
        add_action('admin_enqueue_scripts', [$this, 'maybe_include_jquery'];
        add_action('admin_menu', [$this, 'add_options_page'];
        add_action('admin_init', [$this, 'register_settings'];
        add_action('admin_init', [$this, 'maybe_reset_settings'];
        add_action('admin_init', [$this, 'maybe_migrate_settings'];
        add_action('all_admin_notices', [$this, 'notify_if_reset_successful'];
        add_action('all_admin_notices', [$this, 'notify_json_migrate_status'];

        $default_settings = AADSSO_Settings::get_defaults();
        $this->settings = get_option('aadsso_settings', $default_settings);
        foreach ($default_settings as $key => $default_value) {
            if (!isset($this->settings[$key])) {
                $this->settings[$key] = $default_value;
            }
        }
    }

    public function maybe_reset_settings(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (!isset($_GET['aadsso_nonce'])) {
            return;
        }

        $nonce = sanitize_text_field(wp_unslash($_GET['aadsso_nonce']));

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

        $nonce = isset($_GET['aadsso_nonce']) ? sanitize_text_field(wp_unslash($_GET['aadsso_nonce'])) : '';
        if ('' === $nonce
            || !wp_verify_nonce($nonce, 'aadsso_migrate_from_json')
            || !\defined('AADSSO_SETTINGS_PATH')
            || !file_exists(AADSSO_SETTINGS_PATH)
        ) {
            return;
        }

        $json_content = file_get_contents(AADSSO_SETTINGS_PATH);
        if (false === $json_content) {
            wp_safe_redirect(add_query_arg('aadsso_migrate_from_json_status', 'invalid_json',
                admin_url('options-general.php?page=aadsso_settings')));
            exit;
        }

        $legacy_settings = json_decode($json_content, true);
        $json_error = json_last_error();
        if (null === $legacy_settings && \JSON_ERROR_NONE !== $json_error) {
            AADSSO_Logger::log_error('JSON decode error during migration: ' . json_last_error_msg());
            wp_safe_redirect(add_query_arg('aadsso_migrate_from_json_status', 'invalid_json',
                admin_url('options-general.php?page=aadsso_settings')));
            exit;
        }

        if (isset($legacy_settings['aad_group_to_wp_role_map']) && is_array($legacy_settings['aad_group_to_wp_role_map'])) {
            // aad_group_to_wp_role_map[group_id] = role_slug - convert to role_map format for UI compatibility
            $legacy_settings['role_map'] = [];
            foreach ($legacy_settings['aad_group_to_wp_role_map'] as $group_id => $role_slug) {
                $role_slug = sanitize_text_field($role_slug);
                $group_id = sanitize_text_field($group_id);
                if (empty($role_slug) || empty($group_id)) {
                    continue;
                }
                // Store as role_slug => array of group_ids (matching UI format)
                if (!isset($legacy_settings['role_map'][$role_slug])) {
                    $legacy_settings['role_map'][$role_slug] = [$group_id];
                } else {
                    $legacy_settings['role_map'][$role_slug][] = $group_id;
                }
            }
        }

        $sanitized_settings = $this->sanitize_settings($legacy_settings);
        update_option('aadsso_settings', $sanitized_settings);

        $can_delete = is_writable(AADSSO_SETTINGS_PATH) && is_writable(\dirname(AADSSO_SETTINGS_PATH));
        if ($can_delete) {
            unlink(AADSSO_SETTINGS_PATH);
            wp_safe_redirect(add_query_arg('aadsso_migrate_from_json_status', 'success',
                admin_url('options-general.php?page=aadsso_settings')));
        } else {
            wp_safe_redirect(add_query_arg('aadsso_migrate_from_json_status', 'manual',
                admin_url('options-general.php?page=aadsso_settings')));
        }
        exit;
    }

    public function notify_json_migrate_status(): void
    {
        if (!isset($_GET['aadsso_migrate_from_json_status'])) {
            return;
        }

        $status = sanitize_text_field(wp_unslash($_GET['aadsso_migrate_from_json_status']));

        if ('success' === $status) {
            echo '<div id="message" class="notice notice-success"><p>'
                . esc_html__('Legacy settings have been migrated and the old configuration file has been deleted.',
                    'aad-sso-wordpress')
                . ' ' . esc_html__('To finish migration, unset AADSSO_SETTINGS_PATH from wp-config.php.',
                    'aad-sso-wordpress') . '</p></div>';
        } elseif ('manual' === $status) {
            echo '<div id="message" class="notice notice-warning"><p>'
                . esc_html__('Legacy settings have been migrated successfully.', 'aad-sso-wordpress') . ' '
                . sprintf(esc_html__('To finish migration, delete the file at the path %s.',
                    'aad-sso-wordpress'), '<code>' . esc_html(AADSSO_SETTINGS_PATH) . '</code>')
                . ' ' . sprintf(esc_html__('Then, unset %s from %s.', 'aad-sso-wordpress'),
                    '<code>AADSSO_SETTINGS_PATH</code>', '<code>wp-config.php</code>') . '</p></div>';
        } elseif ('invalid_json' === $status) {
            echo '<div id="message" class="notice notice-error"><p>'
                . sprintf(esc_html__('Legacy settings could not be migrated from %s.', 'aad-sso-wordpress'),
                    '<code>' . esc_html(AADSSO_SETTINGS_PATH) . '</code>')
                . ' ' . esc_html__('File could not be parsed as JSON. Delete the file, or check its syntax.',
                    'aad-sso-wordpress') . '</p></div>';
        }
    }

    public function notify_if_reset_successful(): void
    {
        if (!isset($_GET['aadsso_reset'])) {
            return;
        }

        $status = sanitize_text_field(wp_unslash($_GET['aadsso_reset']));

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
        $this->options_page_id = add_options_page(
            esc_html__('Microsoft Entra ID Settings', 'aad-sso-wordpress'),
            esc_html__('Microsoft Entra ID', 'aad-sso-wordpress'),
            'manage_options',
            'aadsso_settings',
            array($this, 'render_admin_page')
        );
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
            array($this, 'sanitize_settings')
        );

        add_settings_section(
            'aadsso_settings_general',
            esc_html__('General', 'aad-sso-wordpress'),
            array($this, 'settings_general_info'),
            'aadsso_settings_page'
        );

        add_settings_section(
            'aadsso_settings_advanced',
            esc_html__('Advanced', 'aad-sso-wordpress'),
            array($this, 'settings_advanced_info'),
            'aadsso_settings_page'
        );

        add_settings_field(
            'org_display_name',
            esc_html__('Display name', 'aad-sso-wordpress'),
            array($this, 'org_display_name_callback'),
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'org_domain_hint',
            esc_html__('Domain hint', 'aad-sso-wordpress'),
            array($this, 'org_domain_hint_callback'),
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'client_id',
            esc_html__('Client ID', 'aad-sso-wordpress'),
            array($this, 'client_id_callback'),
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'client_secret',
            esc_html__('Client secret', 'aad-sso-wordpress'),
            array($this, 'client_secret_callback'),
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'redirect_uri',
            esc_html__('Redirect URL', 'aad-sso-wordpress'),
            array($this, 'redirect_uri_callback'),
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'logout_redirect_uri',
            esc_html__('Logout redirect URL', 'aad-sso-wordpress'),
            array($this, 'logout_redirect_uri_callback'),
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'enable_full_logout',
            esc_html__('Enable full logout', 'aad-sso-wordpress'),
            array($this, 'enable_full_logout_callback'),
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'field_to_match_to_upn',
            esc_html__('Field to match to UPN', 'aad-sso-wordpress'),
            array($this, 'field_to_match_to_upn_callback'),
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'match_on_upn_alias',
            esc_html__('Match on alias of the UPN', 'aad-sso-wordpress'),
            array($this, 'match_on_upn_alias_callback'),
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'enable_auto_provisioning',
            esc_html__('Enable auto-provisioning', 'aad-sso-wordpress'),
            array($this, 'enable_auto_provisioning_callback'),
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'enable_auto_forward_to_aad',
            esc_html__('Enable auto-forward to Microsoft Entra ID', 'aad-sso-wordpress'),
            array($this, 'enable_auto_forward_to_aad_callback'),
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'enable_aad_group_to_wp_role',
            esc_html__('Enable Microsoft Entra ID group to WordPress role association', 'aad-sso-wordpress'),
            array($this, 'enable_aad_group_to_wp_role_callback'),
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'default_wp_role',
            esc_html__('Default WordPress role if not in Microsoft Entra ID group', 'aad-sso-wordpress'),
            array($this, 'default_wp_role_callback'),
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'role_map',
            esc_html__('WordPress role to Microsoft Entra ID group map', 'aad-sso-wordpress'),
            array($this, 'role_map_callback'),
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'openid_configuration_endpoint',
            esc_html__('OpenID Connect configuration endpoint', 'aad-sso-wordpress'),
            array($this, 'openid_configuration_endpoint_callback'),
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'aadsso_settings_security_info',
            esc_html__('Security Information', 'aad-sso-wordpress'),
            array($this, 'security_info_callback'),
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

    public function sanitize_settings(array $input): array
    {
        $sanitized = [];

        $sanitized['org_display_name'] = sanitize_text_field($input['org_display_name'] ?? '');
        $sanitized['org_domain_hint'] = sanitize_text_field($input['org_domain_hint'] ?? '');
        $sanitized['client_id'] = sanitize_text_field($input['client_id'] ?? '');
        $sanitized['client_secret'] = sanitize_text_field($input['client_secret'] ?? '');
        $sanitized['redirect_uri'] = esc_url_raw($input['redirect_uri'] ?? '');
        $sanitized['logout_redirect_uri'] = esc_url_raw($input['logout_redirect_uri'] ?? '');

        $sanitized['enable_full_logout'] = !empty($input['enable_full_logout']);
        $sanitized['field_to_match_to_upn'] = \in_array($input['field_to_match_to_upn'] ?? '', ['login', 'email'], true)
            ? $input['field_to_match_to_upn']
            : 'email';
        $sanitized['match_on_upn_alias'] = !empty($input['match_on_upn_alias']);
        $sanitized['enable_auto_provisioning'] = !empty($input['enable_auto_provisioning']);
        $sanitized['enable_auto_forward_to_aad'] = !empty($input['enable_auto_forward_to_aad']);
        $sanitized['enable_aad_group_to_wp_role'] = !empty($input['enable_aad_group_to_wp_role']);

        $default_wp_role = sanitize_text_field($input['default_wp_role'] ?? '');
        $valid_roles = array_keys($this->get_editable_roles());
        $sanitized['default_wp_role'] = in_array($default_wp_role, $valid_roles, true) ? $default_wp_role : '';

        $sanitized['openid_configuration_endpoint'] = esc_url_raw(
            $input['openid_configuration_endpoint'] ??
            'https://login.microsoftonline.com/common/.well-known/openid-configuration'
        );

        // OpenID configuration endpoints (loaded from OpenID config, may be set manually)
        $sanitized['authorization_endpoint'] = esc_url_raw($input['authorization_endpoint'] ?? '');
        $sanitized['token_endpoint'] = esc_url_raw($input['token_endpoint'] ?? '');
        $sanitized['jwks_uri'] = esc_url_raw($input['jwks_uri'] ?? '');
        $sanitized['end_session_endpoint'] = esc_url_raw($input['end_session_endpoint'] ?? '');

        // Graph API settings
        $sanitized['graph_endpoint'] = esc_url_raw($input['graph_endpoint'] ?? 'https://graph.microsoft.com');
        $sanitized['graph_version'] = \in_array($input['graph_version'] ?? '', ['v1.0', 'beta'], true)
            ? $input['graph_version']
            : 'v1.0';

        if (!empty($input['role_map']) && is_array($input['role_map'])) {
            $sanitized['role_map'] = [];
            $valid_roles = array_keys($this->get_editable_roles());
            foreach ($input['role_map'] as $role => $groups) {
                $role = sanitize_text_field($role);
                $groups = is_array($groups) ? $groups : explode(',', $groups);
                if (!empty($role) && in_array($role, $valid_roles, true)) {
                    $group_ids = [];
                    foreach ($groups as $group_id) {
                        $group_id = sanitize_text_field(trim((string) $group_id));
                        if (!empty($group_id)) {
                            $group_ids[] = $group_id;
                        }
                    }
                    if (!empty($group_ids)) {
                        $sanitized['role_map'][$role] = $group_ids;
                    }
                }
            }
        }

        return $sanitized;
    }

    public function settings_general_info(): void
    {
        echo '<p>' . esc_html__('Configure the basic settings for Microsoft Entra ID single sign-on.',
                'aad-sso-wordpress') . '</p>';
    }

    public function settings_advanced_info(): void
    {
        echo '<p>' . esc_html__('Configure advanced settings for Microsoft Entra ID single sign-on.',
                'aad-sso-wordpress') . '</p>';
    }

    public function org_display_name_callback(): void
    {
        $this->render_text_field('org_display_name');
        echo '<p class="description">' . esc_html__('Display Name will be shown on the WordPress login screen.',
                'aad-sso-wordpress') . '</p>';
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
        $value = isset($this->settings['client_secret']) ? esc_attr($this->settings['client_secret']) : '';
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
        $selected = isset($this->settings['field_to_match_to_upn']) ? $this->settings['field_to_match_to_upn'] : 'email';
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
                __('Match WordPress users based on the alias of their Microsoft Entra ID '
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
            printf(
                '<option value="%s"%s>%s</option>',
                esc_attr($role_slug),
                selected($this->settings['default_wp_role'], $role_slug, false),
                esc_html($role['name'])
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

        $role_map = $this->settings['role_map'] ?? [];
        $roles = $this->get_editable_roles();
        $row_index = 0;

        foreach ($roles as $role_slug => $role) {
            $group_ids = $role_map[$role_slug] ?? '';
            echo '<tr class="role_map_row">';
            echo '<td>' . esc_html($role['name']) . '</td>';
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
        echo ' <a href="#" class="button button-secondary" onclick="jQuery(\'#openid_configuration_endpoint\').val(\''
            . esc_url(AADSSO_Settings::get_defaults('openid_configuration_endpoint'))
            . '\'); return false;">' . esc_html__('Set default', 'aad-sso-wordpress') . '</a>';
        echo '<p class="description">' . wp_kses_post(
            __('The OpenID Connect configuration endpoint to use. To support Microsoft '
                . 'Accounts and external users (users invited in from other Microsoft Entra ID '
                . 'directories, known sometimes as "B2B users") you must use: '
                . '<code>https://login.microsoftonline.com/{tenant-id}/.well-known/openid-configuration</code>, '
                . 'where <code>{tenant-id}</code> is the tenant ID or a verified domain name of your directory.',
                'aad-sso-wordpress'
            )
        ) . '</p>';
    }

    public function render_text_field(string $name): void
    {
        $value = isset($this->settings[$name]) ? esc_attr($this->settings[$name]) : '';
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
        return $screen && $screen->id === $this->options_page_id;
    }

    public function maybe_include_jquery(): void
    {
        if ($this->is_on_options_page()) {
            wp_enqueue_script('jquery');
        }
    }

    private function get_editable_roles(): array
    {
        if (!\function_exists('wp_roles')) {
            global $wp_roles;
            return $wp_roles->roles ?? [];
        }
        $roles = wp_roles();
        return $roles->roles ?? [];
    }
}
