<?php

declare(strict_types=1);

class AADSSO_Settings
{
    private static ?AADSSO_Settings $instance = null;

    public string $client_id = '';
    public string $client_secret = '';
    public string $redirect_uri = '';
    public string $logout_redirect_uri = '';
    public string $org_display_name = '';
    public string $org_domain_hint = '';
    public string $field_to_match_to_upn = '';
    public bool $match_on_upn_alias = false;
    public bool $enable_auto_provisioning = false;
    public bool $enable_auto_forward_to_aad = false;
    public bool $enable_aad_group_to_wp_role = false;
    public array $aad_group_to_wp_role_map = array();
    public ?string $default_wp_role = null;
    public bool $enable_full_logout = false;
    public string $openid_configuration_endpoint = 'https://login.microsoftonline.com/common/.well-known/openid-configuration';
    public string $authorization_endpoint = '';
    public string $token_endpoint = '';
    public string $jwks_uri = '';
    public string $end_session_endpoint = '';
    public string $graph_endpoint = 'https://graph.microsoft.com';
    public string $graph_version = 'v1.0';

    public static function get_defaults(?string $key = null): mixed
    {
        $defaults = array(
            'org_display_name' => get_bloginfo('name'),
            'field_to_match_to_upn' => 'email',
            'default_wp_role' => null,
            'enable_auto_provisioning' => false,
            'match_on_upn_alias' => false,
            'enable_auto_forward_to_aad' => false,
            'enable_aad_group_to_wp_role' => false,
            'redirect_uri' => wp_login_url(),
            'logout_redirect_uri' => wp_login_url(),
            'openid_configuration_endpoint' => 'https://login.microsoftonline.com/common/.well-known/openid-configuration',
        );

        if (null === $key) {
            return $defaults;
        }

        return $defaults[$key] ?? null;
    }

    public static function get_instance(): self
    {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public static function init(): self
    {
        $instance = self::get_instance();
        $instance->load_settings(get_option('aadsso_settings'));

        $openid_configuration = get_transient('aadsso_openid_configuration');
        $force_reload = isset($_GET['aadsso_reload_openid_config']);

        if (false === $openid_configuration || $force_reload) {
            $remote_response = self::get_remote_contents(
                esc_url_raw($instance->openid_configuration_endpoint)
            );

            if (!empty($remote_response)) {
                $openid_configuration = json_decode($remote_response, true);
                if (is_array($openid_configuration)) {
                    set_transient('aadsso_openid_configuration', $openid_configuration, 3600);
                }
            }
        }

        if (!empty($openid_configuration) && is_array($openid_configuration)) {
            $instance->load_settings($openid_configuration);
        }

        return $instance;
    }

    public static function get_remote_contents(string $url): string
    {
        $response = wp_remote_get(
            esc_url_raw($url),
            array(
                'timeout' => 15,
                'sslverify' => true,
            )
        );

        if (is_wp_error($response)) {
            AADSSO::debug_log(
                'Failed to fetch remote contents: ' . $response->get_error_message(),
                100
            );
            return '';
        }

        $file_contents = wp_remote_retrieve_body($response);
        return is_string($file_contents) ? $file_contents : '';
    }

    public function load_settings(?array $settings): self
    {
        if (!is_array($settings) || empty($settings)) {
            return $this;
        }

        if (!empty($settings['role_map']) && is_array($settings['role_map'])) {
            $settings['aad_group_to_wp_role_map'] = array();
            foreach ($settings['role_map'] as $role_slug => $group_ids_list) {
                if (empty($group_ids_list)) {
                    continue;
                }
                $group_ids = explode(',', $group_ids_list);
                if (!empty($group_ids)) {
                    foreach ($group_ids as $group_id) {
                        $group_id = trim(sanitize_text_field($group_id));
                        if (!empty($group_id)
                            && !isset($settings['aad_group_to_wp_role_map'][$group_id])
                        ) {
                            $settings['aad_group_to_wp_role_map'][$group_id] = sanitize_text_field($role_slug);
                        }
                    }
                }
            }
        }

        foreach ($settings as $key => $value) {
            if (property_exists($this, $key)) {
                $this->{$key} = $this->sanitize_value($key, $value);
            }
        }
        return $this;
    }

    private function sanitize_value(string $key, mixed $value): mixed
    {
        $url_fields = array(
            'redirect_uri',
            'logout_redirect_uri',
            'authorization_endpoint',
            'token_endpoint',
            'jwks_uri',
            'end_session_endpoint',
            'openid_configuration_endpoint',
            'graph_endpoint',
        );

        if (in_array($key, $url_fields, true)) {
            return esc_url_raw((string) $value);
        }

        return match ($key) {
            'client_id', 'client_secret',
            'org_display_name', 'org_domain_hint',
            'field_to_match_to_upn', 'default_wp_role',
            'graph_version' => sanitize_text_field((string) $value),

            'enable_auto_provisioning', 'enable_auto_forward_to_aad', 'enable_aad_group_to_wp_role',
            'enable_full_logout', 'match_on_upn_alias' => (bool) $value,

            'aad_group_to_wp_role_map' => is_array($value) ? $value : array(),

            default => $value,
        };
    }
}