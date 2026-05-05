<?php

declare(strict_types=1);

use Symfony\Component\OptionsResolver\OptionsResolver;

class AADSSO_Settings
{
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
    public array $aad_group_to_wp_role_map = [];
    public ?string $default_wp_role = null;
    public bool $enable_full_logout = false;
    public string $openid_configuration_endpoint = 'https://login.microsoftonline.com/common/.well-known/openid-configuration';
    public string $authorization_endpoint = '';
    public string $token_endpoint = '';
    public string $jwks_uri = '';
    public string $end_session_endpoint = '';
    public string $graph_endpoint = 'https://graph.microsoft.com';
    public string $graph_version = 'v1.0';

    private static ?self $instance = null;
    private static ?OptionsResolver $options_resolver = null;

    public static function get_defaults(?string $key = null): mixed
    {
        $defaults = [
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
        ];

        if (null === $key) {
            return $defaults;
        }

        return $defaults[$key] ?? null;
    }

    public static function get_instance(): self
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public static function get_options_resolver(): OptionsResolver
    {
        if (null === self::$options_resolver) {
            self::$options_resolver = new OptionsResolver();

            self::$options_resolver->define('client_id')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('client_secret')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('redirect_uri')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('logout_redirect_uri')
                ->allowedTypes('string')
                ->default(wp_login_url());

            self::$options_resolver->define('org_display_name')
                ->allowedTypes('string')
                ->default(get_bloginfo('name'));

            self::$options_resolver->define('org_domain_hint')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('field_to_match_to_upn')
                ->allowedTypes('string')
                ->default('email')
                ->allowedValues('email', 'login');

            self::$options_resolver->define('match_on_upn_alias')
                ->allowedTypes('bool')
                ->default(false);

            self::$options_resolver->define('enable_auto_provisioning')
                ->allowedTypes('bool')
                ->default(false);

            self::$options_resolver->define('enable_auto_forward_to_aad')
                ->allowedTypes('bool')
                ->default(false);

            self::$options_resolver->define('enable_aad_group_to_wp_role')
                ->allowedTypes('bool')
                ->default(false);

            self::$options_resolver->define('aad_group_to_wp_role_map')
                ->allowedTypes('array')
                ->default([]);

            self::$options_resolver->define('default_wp_role')
                ->allowedTypes('null', 'string')
                ->default(null);

            self::$options_resolver->define('enable_full_logout')
                ->allowedTypes('bool')
                ->default(false);

            self::$options_resolver->define('openid_configuration_endpoint')
                ->allowedTypes('string')
                ->default('https://login.microsoftonline.com/common/.well-known/openid-configuration');

            self::$options_resolver->define('authorization_endpoint')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('token_endpoint')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('jwks_uri')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('end_session_endpoint')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('graph_endpoint')
                ->allowedTypes('string')
                ->default('https://graph.microsoft.com');

            self::$options_resolver->define('graph_version')
                ->allowedTypes('string')
                ->default('v1.0')
                ->allowedValues('v1.0', 'beta');

            self::$options_resolver->define('role_map')
                ->allowedTypes('array')
                ->default([]);
        }

        return self::$options_resolver;
    }

    public static function init(): self
    {
        $instance = self::get_instance();

        $plugin_settings = get_option('aadsso_settings');
        if (\is_array($plugin_settings) && !empty($plugin_settings)) {
            $instance->load_settings($plugin_settings);
        }

        $openid_configuration = self::get_cached_openid_configuration();

        if (!empty($openid_configuration) && \is_array($openid_configuration)) {
            $filtered_config = self::filter_to_known_settings($openid_configuration);
            if (!empty($filtered_config)) {
                $instance->load_settings($filtered_config);
            }
        }

        return $instance;
    }

    private static function filter_to_known_settings(array $settings): array
    {
        $resolver = self::get_options_resolver();
        $defined_options = array_keys($resolver->resolve([]));

        return array_filter(
            $settings,
            fn(string $key): bool => \in_array($key, $defined_options, true),
            ARRAY_FILTER_USE_KEY
        );
    }

    private static function get_cached_openid_configuration(): ?array
    {
        $force_reload = isset($_GET['aadsso_reload_openid_config']);

        if ($force_reload && current_user_can('manage_options') && check_admin_referer('aadsso_reload_openid_config')) {
            $config = self::fetch_openid_configuration();

            if (!empty($config)) {
                try {
                    $cache = AADSSO_Logger::get_cache();
                    $cache->set('aadsso_openid_configuration', $config, 3600);
                } catch (\Throwable $e) {
                    AADSSO_Logger::log_exception($e, 'Cache write failed for OpenID configuration');
                }
            }

            return $config;
        }

        $cache = AADSSO_Logger::get_cache();

        try {
            $cached = $cache->get('aadsso_openid_configuration');
            if (\is_array($cached) && !empty($cached)) {
                return $cached;
            }
        } catch (\Throwable $e) {
            AADSSO_Logger::log_exception($e, 'Cache read failed for OpenID configuration');
        }

        $config = self::fetch_openid_configuration();

        if (!empty($config)) {
            try {
                $cache->set('aadsso_openid_configuration', $config, 3600);
            } catch (\Throwable $e) {
                AADSSO_Logger::log_exception($e, 'Cache write failed for OpenID configuration');
            }
        }

        return $config;
    }

    private static function fetch_openid_configuration(): ?array
    {
        $instance = self::get_instance();
        $remote_response = self::get_remote_contents(
            esc_url_raw($instance->openid_configuration_endpoint)
        );

        if (!empty($remote_response)) {
            $openid_configuration = json_decode($remote_response, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                AADSSO_Logger::log_error('OpenID configuration JSON decode error: ' . json_last_error_msg());
                return null;
            }

            if (\is_array($openid_configuration) && !empty($openid_configuration)) {
                return $openid_configuration;
            }
        }

        return null;
    }

    public static function get_remote_contents(string $url): string
    {
        try {
            $response = AADSSO_HttpClient::get_instance()->get($url, [
                'headers' => [
                    'Accept' => 'application/json',
                ],
            ]);

            $status_code = $response->getStatusCode();

            if ($status_code >= 400) {
                AADSSO_Logger::log_error(
                    'Failed to fetch remote contents: HTTP ' . $status_code
                );
                return '';
            }

            $body = $response->getBody()->getContents();

            return \is_string($body) ? $body : '';
        } catch (\Throwable $e) {
            AADSSO_Logger::log_error(
                'Failed to fetch remote contents: ' . $e->getMessage()
            );

            return '';
        }
    }

    private static function sanitize_setting(string $key, mixed $value): mixed
    {
        $url_fields = [
            'redirect_uri',
            'logout_redirect_uri',
            'authorization_endpoint',
            'token_endpoint',
            'jwks_uri',
            'end_session_endpoint',
            'openid_configuration_endpoint',
            'graph_endpoint',
        ];

        if (\in_array($key, $url_fields, true)) {
            return esc_url_raw((string) $value);
        }

        return match ($key) {
            'client_id' => sanitize_text_field((string) $value),
            'client_secret' => (string) $value,
            'org_display_name', 'org_domain_hint',
            'field_to_match_to_upn', 'default_wp_role',
            'graph_version' => sanitize_text_field((string) $value),
            'match_on_upn_alias',
            'enable_auto_provisioning',
            'enable_auto_forward_to_aad',
            'enable_aad_group_to_wp_role',
            'enable_full_logout' => (bool) $value,
            'aad_group_to_wp_role_map' => \is_array($value) ? $value : [],
            default => $value,
        };
    }

    public function load_settings(?array $settings): self
    {
        if (!\is_array($settings) || empty($settings)) {
            return $this;
        }

        if (!empty($settings['role_map']) && \is_array($settings['role_map'])) {
            $settings['aad_group_to_wp_role_map'] = [];
            foreach ($settings['role_map'] as $role_slug => $group_ids_list) {
                if (empty($group_ids_list)) {
                    continue;
                }
                if (\is_array($group_ids_list)) {
                    foreach ($group_ids_list as $group_id) {
                        $group_id = trim(sanitize_text_field((string) $group_id));
                        if (!empty($group_id) && !isset($settings['aad_group_to_wp_role_map'][$group_id])) {
                            $settings['aad_group_to_wp_role_map'][$group_id] = sanitize_text_field((string) $role_slug);
                        }
                    }
                } else {
                    $group_ids = explode(',', (string) $group_ids_list);
                    if (!empty($group_ids)) {
                        foreach ($group_ids as $group_id) {
                            $group_id = trim(sanitize_text_field($group_id));
                            if (!empty($group_id)
                                && !isset($settings['aad_group_to_wp_role_map'][$group_id])
                            ) {
                                $settings['aad_group_to_wp_role_map'][$group_id] = sanitize_text_field((string) $role_slug);
                            }
                        }
                    }
                }
            }
        }

        try {
            $resolved_settings = self::get_options_resolver()->resolve($settings);
            foreach ($resolved_settings as $key => $value) {
                if (property_exists($this, $key)) {
                    $this->{$key} = self::sanitize_setting($key, $value);
                }
            }
        } catch (\Throwable $e) {
            AADSSO_Logger::log_exception($e, 'Failed to resolve settings with OptionsResolver');
        }

        return $this;
    }
}