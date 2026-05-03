<?php

declare(strict_types=1);

class AADSSO_Settings_Page
{
    private array $settings;
    private $options_page_id;

    public function __construct()
    {
        add_action('admin_enqueue_scripts', [$this, 'maybe_include_jquery']);
        add_action('admin_menu', [$this, 'add_options_page']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_init', [$this, 'maybe_reset_settings']);
        add_action('admin_init', [$this, 'maybe_migrate_settings']);
        add_action('all_admin_notices', [$this, 'notify_if_reset_successful']);
        add_action('all_admin_notices', [$this, 'notify_json_migrate_status']);

        $_SERVER['REQUEST_URI'] = remove_query_arg('aadsso_reset', $_SERVER['REQUEST_URI']);
        $_SERVER['REQUEST_URI'] = remove_query_arg('aadsso_migrate_from_json_status', $_SERVER['REQUEST_URI']);

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
        if (!isset($_GET['aadsso_nonce']) || !wp_verify_nonce($_GET['aadsso_nonce'], 'aadsso_reset_settings')) {
            return;
        }

        delete_option('aadsso_settings');
        wp_safe_redirect(admin_url('options-general.php?page=aadsso_settings&aadsso_reset=success'));
        exit;
    }

    public function maybe_migrate_settings(): void
    {
        $should_migrate = isset($_GET['aadsso_nonce'])
            && wp_verify_nonce($_GET['aadsso_nonce'], 'aadsso_migrate_from_json')
            && defined('AADSSO_SETTINGS_PATH')
            && file_exists(AADSSO_SETTINGS_PATH);

        if (!$should_migrate) {
            return;
        }

        $legacy_settings = json_decode(file_get_contents(AADSSO_SETTINGS_PATH), true);

        if (null === $legacy_settings) {
            wp_safe_redirect(admin_url('options-general.php?page=aadsso_settings&aadsso_migrate_from_json_status=invalid_json'));
            exit;
        }

        if (isset($legacy_settings['aad_group_to_wp_role_map'])) {
            $legacy_settings['role_map'] = [];
            foreach ($legacy_settings['aad_group_to_wp_role_map'] as $group_id => $role_slug) {
                if (!isset($legacy_settings['role_map'][$role_slug])) {
                    $legacy_settings['role_map'][$role_slug] = $group_id;
                } else {
                    $legacy_settings['role_map'][$role_slug] .= ',' . $group_id;
                }
            }
        }

        $sanitized_settings = $this->sanitize_settings($legacy_settings);
        update_option('aadsso_settings', $sanitized_settings);

        $parent_dir = dirname(AADSSO_SETTINGS_PATH);
        if (is_writable(AADSSO_SETTINGS_PATH) && is_writable($parent_dir) && unlink(AADSSO_SETTINGS_PATH)) {
            wp_safe_redirect(admin_url('options-general.php?page=aadsso_settings&aadsso_migrate_from_json_status=success'));
        } else {
            wp_safe_redirect(admin_url('options-general.php?page=aadsso_settings&aadsso_migrate_from_json_status=manual'));
        }
        exit;
    }

    public function notify_json_migrate_status(): void
    {
        if (!isset($_GET['aadsso_migrate_from_json_status'])) {
            return;
        }

        $status = sanitize_key($_GET['aadsso_migrate_from_json_status']);

        if ('success' === $status) {
            echo '<div id="message" class="notice notice-success"><p>'
                . esc_html__('Legacy settings have been migrated and the old configuration file has been deleted.', 'aad-sso-wordpress')
                . ' ' . esc_html__('To finish migration, unset AADSSO_SETTINGS_PATH from wp-config.php.', 'aad-sso-wordpress')
                . '</p></div>';
        } elseif ('manual' === $status) {
            echo '<div id="message" class="notice notice-warning"><p>'
                . esc_html__('Legacy settings have been migrated successfully.', 'aad-sso-wordpress') . ' '
                . sprintf(esc_html__('To finish migration, delete the file at the path %s.', 'aad-sso-wordpress'), '<code>' . esc_html(AADSSO_SETTINGS_PATH) . '</code>')
                . ' ' . sprintf(esc_html__('Then, unset AADSSO_SETTINGS_PATH from wp-config.php.', 'aad-sso-wordpress'))
                . '</p></div>';
        } elseif ('invalid_json' === $status) {
            echo '<div id="message" class="notice notice-error"><p>'
                . sprintf(esc_html__('Legacy settings could not be migrated from %s.', 'aad-sso-wordpress'), '<code>' . esc_html(AADSSO_SETTINGS_PATH) . '</code>')
                . ' ' . esc_html__('File could not be parsed as JSON.', 'aad-sso-wordpress')
                . '</p></div>';
        }
    }

    public function notify_if_reset_successful(): void
    {
        if (!isset($_GET['aadsso_reset']) || 'success' !== $_GET['aadsso_reset']) {
            return;
        }

        echo '<div id="message" class="notice notice-warning"><p>'
            . esc_html__('Single Sign-on with Microsoft Entra ID settings have been reset to default.', 'aad-sso-wordpress')
            . '</p></div>';
    }

    public function add_options_page(): void
    {
        $this->options_page_id = add_options_page(
            __('Microsoft Entra ID Settings', 'aad-sso-wordpress'),
            'Microsoft Entra ID',
            'manage_options',
            'aadsso_settings',
            [$this, 'render_admin_page']
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
            [$this, 'sanitize_settings']
        );

        add_settings_section(
            'aadsso_settings_general',
            __('General', 'aad-sso-wordpress'),
            [$this, 'settings_general_info'],
            'aadsso_settings_page'
        );

        add_settings_section(
            'aadsso_settings_advanced',
            __('Advanced', 'aad-sso-wordpress'),
            [$this, 'settings_advanced_info'],
            'aadsso_settings_page'
        );

        add_settings_field(
            'org_display_name',
            __('Display name', 'aad-sso-wordpress'),
            [$this, 'org_display_name_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'client_id',
            __('Client ID', 'aad-sso-wordpress'),
            [$this, 'client_id_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'client_secret',
            __('Client Secret', 'aad-sso-wordpress'),
            [$this, 'client_secret_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'redirect_uri',
            __('Redirect URI', 'aad-sso-wordpress'),
            [$this, 'redirect_uri_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'logout_redirect_uri',
            __('Logout Redirect URI', 'aad-sso-wordpress'),
            [$this, 'logout_redirect_uri_callback'],
            'aadsso_settings_page',
            'aadsso_settings_general'
        );

        add_settings_field(
            'field_to_match_to_upn',
            __('Field to match to UPN', 'aad-sso-wordpress'),
            [$this, 'field_to_match_to_upn_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'match_on_upn_alias',
            __('Match on alias of the UPN', 'aad-sso-wordpress'),
            [$this, 'match_on_upn_alias_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'enable_auto_provisioning',
            __('Enable auto-provisioning', 'aad-sso-wordpress'),
            [$this, 'enable_auto_provisioning_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'enable_auto_forward_to_aad',
            __('Enable auto-forward to Microsoft Entra ID', 'aad-sso-wordpress'),
            [$this, 'enable_auto_forward_to_aad_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'enable_aad_group_to_wp_role',
            __('Enable Microsoft Entra ID group to WordPress role association', 'aad-sso-wordpress'),
            [$this, 'enable_aad_group_to_wp_role_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'default_wp_role',
            __('Default WordPress role if not in Microsoft Entra ID group', 'aad-sso-wordpress'),
            [$this, 'default_wp_role_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'openid_configuration_endpoint',
            __('OpenID Configuration Endpoint', 'aad-sso-wordpress'),
            [$this, 'openid_configuration_endpoint_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );

        add_settings_field(
            'enable_full_logout',
            __('Enable full logout', 'aad-sso-wordpress'),
            [$this, 'enable_full_logout_callback'],
            'aadsso_settings_page',
            'aadsso_settings_advanced'
        );
    }

    public function settings_general_info(): void
    {
        echo '<p>' . esc_html__('Configure the basic settings for Microsoft Entra ID Single Sign-on.', 'aad-sso-wordpress') . '</p>';
    }

    public function settings_advanced_info(): void
    {
        echo '<p>' . esc_html__('Configure advanced settings for Microsoft Entra ID Single Sign-on.', 'aad-sso-wordpress') . '</p>';
    }

    public function sanitize_settings(array $input): array
    {
        $sanitized = [];

        $sanitized['org_display_name'] = sanitize_text_field($input['org_display_name'] ?? '');
        $sanitized['client_id'] = sanitize_text_field($input['client_id'] ?? '');
        $sanitized['client_secret'] = sanitize_text_field($input['client_secret'] ?? '');
        $sanitized['redirect_uri'] = esc_url_raw($input['redirect_uri'] ?? '');
        $sanitized['logout_redirect_uri'] = esc_url_raw($input['logout_redirect_uri'] ?? '');
        $sanitized['org_domain_hint'] = sanitize_text_field($input['org_domain_hint'] ?? '');
        $sanitized['field_to_match_to_upn'] = in_array($input['field_to_match_to_upn'] ?? '', ['email', 'login'], true)
            ? $input['field_to_match_to_upn']
            : 'email';

        $sanitized['match_on_upn_alias'] = !empty($input['match_on_upn_alias']);
        $sanitized['enable_auto_provisioning'] = !empty($input['enable_auto_provisioning']);
        $sanitized['enable_auto_forward_to_aad'] = !empty($input['enable_auto_forward_to_aad']);
        $sanitized['enable_aad_group_to_wp_role'] = !empty($input['enable_aad_group_to_wp_role']);
        $sanitized['enable_full_logout'] = !empty($input['enable_full_logout']);

        $sanitized['default_wp_role'] = sanitize_text_field($input['default_wp_role'] ?? '');

        $sanitized['openid_configuration_endpoint'] = esc_url_raw($input['openid_configuration_endpoint'] ?? '');

        if (!empty($input['role_map']) && is_array($input['role_map'])) {
            $sanitized['role_map'] = [];
            foreach ($input['role_map'] as $role => $groups) {
                $sanitized['role_map'][sanitize_key($role)] = sanitize_text_field($groups);
            }
        }

        return $sanitized;
    }

    public function org_display_name_callback(): void
    {
        $this->render_text_field('org_display_name');
        printf(
            '<p class="description">%s</p>',
            esc_html__('The display name of the organization, used in the link on the WordPress login page.', 'aad-sso-wordpress')
        );
    }

    public function client_id_callback(): void
    {
        $this->render_text_field('client_id');
        printf(
            '<p class="description">%s</p>',
            esc_html__('The client ID of the Microsoft Entra ID application representing this blog.', 'aad-sso-wordpress')
        );
    }

    public function client_secret_callback(): void
    {
        $this->render_text_field('client_secret');
        printf(
            '<p class="description">%s</p>',
            esc_html__('A secret key for the Microsoft Entra ID application representing this blog.', 'aad-sso-wordpress')
        );
    }

    public function redirect_uri_callback(): void
    {
        $this->render_text_field('redirect_uri');
        printf(
            ' <a href="#" class="button button-secondary" onclick="jQuery(\'#redirect_uri\').val(\'%s\'); return false;">%s</a>'
            . '<p class="description">%s</p>',
            esc_js(wp_login_url()),
            esc_html__('Set default', 'aad-sso-wordpress'),
            esc_html__('The URL where the user is redirected to after authenticating with Microsoft Entra ID. This URL must be registered in Microsoft Entra ID as a valid redirect URL.', 'aad-sso-wordpress')
        );
    }

    public function logout_redirect_uri_callback(): void
    {
        $this->render_text_field('logout_redirect_uri');
        printf(
            ' <a href="#" class="button button-secondary" onclick="jQuery(\'#logout_redirect_uri\').val(\'%s\'); return false;">%s</a>'
            . '<p class="description">%s</p>',
            esc_js(wp_login_url()),
            esc_html__('Set default', 'aad-sso-wordpress'),
            esc_html__('The URL where the user is redirected to after signing out of Microsoft Entra ID.', 'aad-sso-wordpress')
        );
    }

    public function field_to_match_to_upn_callback(): void
    {
        $selected = $this->settings['field_to_match_to_upn'] ?? 'email';
        ?>
        <select name="aadsso_settings[field_to_match_to_upn]" id="field_to_match_to_upn">
            <option value="email"<?php selected('email', $selected); ?>>
                <?php echo esc_html__('Email Address', 'aad-sso-wordpress'); ?>
            </option>
            <option value="login"<?php selected('login', $selected); ?>>
                <?php echo esc_html__('Login Name', 'aad-sso-wordpress'); ?>
            </option>
        </select>
        <?php
        printf(
            '<p class="description">%s</p>',
            esc_html__('This specifies the WordPress user field which will be used to match to the Microsoft Entra ID user\'s UserPrincipalName.', 'aad-sso-wordpress')
        );
    }

    public function match_on_upn_alias_callback(): void
    {
        $this->render_checkbox_field(
            'match_on_upn_alias',
            esc_html__('Match WordPress users based on the alias of their Microsoft Entra ID UserPrincipalName. For example, Microsoft Entra ID username bob@example.com will match WordPress user bob.', 'aad-sso-wordpress')
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
        printf(
            '<p class="description">%s</p>',
            esc_html__('This is the default role that users will be assigned to if matching Microsoft Entra ID group to WordPress roles is enabled, but the signed in user isn\'t a member of any of the configured Microsoft Entra ID groups.', 'aad-sso-wordpress')
        );
    }

    public function enable_auto_provisioning_callback(): void
    {
        $this->render_checkbox_field(
            'enable_auto_provisioning',
            esc_html__('Automatically create WordPress users, if needed, for authenticated Microsoft Entra ID users.', 'aad-sso-wordpress')
        );
    }

    public function enable_auto_forward_to_aad_callback(): void
    {
        $this->render_checkbox_field(
            'enable_auto_forward_to_aad',
            esc_html__('Automatically forward users to the Microsoft Entra ID to sign in, skipping the WordPress login screen.', 'aad-sso-wordpress')
        );
    }

    public function enable_aad_group_to_wp_role_callback(): void
    {
        $this->render_checkbox_field(
            'enable_aad_group_to_wp_role',
            esc_html__('Automatically assign WordPress user roles based on Microsoft Entra ID group membership.', 'aad-sso-wordpress')
        );
    }

    public function openid_configuration_endpoint_callback(): void
    {
        $this->render_text_field('openid_configuration_endpoint');
        printf(
            ' <a href="#" class="button button-secondary" onclick="jQuery(\'#openid_configuration_endpoint\').val(\'%s\'); return false;">%s</a>'
            . '<p class="description">%s</p>',
            esc_js(AADSSO_Settings::get_defaults('openid_configuration_endpoint')),
            esc_html__('Set default', 'aad-sso-wordpress'),
            esc_html__('The OpenID Connect configuration endpoint to use.', 'aad-sso-wordpress')
        );
    }

    public function enable_full_logout_callback(): void
    {
        $this->render_checkbox_field(
            'enable_full_logout',
            esc_html__('Do a full logout of Microsoft Entra ID when logging out of WordPress.', 'aad-sso-wordpress')
        );
    }

    public function render_text_field(string $name): void
    {
        $value = isset($this->settings[$name]) ? esc_attr($this->settings[$name]) : '';
        printf(
            '<input class="regular-text" type="text" name="aadsso_settings[%1$s]" id="%1$s" value="%2$s" />',
            esc_attr($name),
            $value
        );
    }

    public function render_checkbox_field(string $name, string $label): void
    {
        printf(
            '<input type="checkbox" name="aadsso_settings[%1$s]" id="%1$s" value="%1$s"%2$s />'
            . '<label for="%1$s">%3$s</label>',
            esc_attr($name),
            checked(!empty($this->settings[$name]), true, false),
            $label
        );
    }

    private function get_editable_roles(): array
    {
        global $wp_roles;
        if (!isset($wp_roles)) {
            $wp_roles = new WP_Roles();
        }
        return $wp_roles->get_names();
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
}