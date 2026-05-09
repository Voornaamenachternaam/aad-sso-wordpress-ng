<?php

declare(strict_types=1);

use Symfony\Component\OptionsResolver\OptionsResolver;

class Settings
{
    public const DEFAULT_OPENID_CONFIGURATION_ENDPOINT = 'https://login.microsoftonline.com/organizations/.well-known/openid-configuration';

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

    /**
     * @var array<string, string>
     */
    public array $aad_group_to_wp_role_map = [];

    public ?string $default_wp_role = null;

    public bool $enable_full_logout = false;

    public string $openid_configuration_endpoint = self::DEFAULT_OPENID_CONFIGURATION_ENDPOINT;

    public string $authorization_endpoint = '';

    public string $token_endpoint = '';

    public string $jwks_uri = '';

    public string $issuer = '';

    public string $end_session_endpoint = '';

    public string $graph_endpoint = 'https://graph.microsoft.com';

    public string $graph_version = 'v1.0';

    public string $custom_scope = '';

    public string $tenantRestrictionMode = 'none';

    public string $expected_tenant_id = '';

    /**
     * @var list<string>
     */
    public array $allowed_tenant_ids = [];

    /**
     * Allowed redirect domains for post-login redirect validation.
     *
     * If non-empty, the redirect_to parameter will only be accepted
     * if it points to a domain in this list. This prevents open redirect
     * vulnerabilities where an attacker could redirect users to a malicious site.
     *
     * @var list<string>
     */
    public array $allowed_redirect_domains = [];

    /**
     * Whether to block external redirects entirely.
     *
     * If true, redirects are only allowed to the current WordPress site domain.
     * This provides defense-in-depth against open redirect attacks.
     */
    public bool $block_external_redirects = false;

    /**
     * @var null|self
     */
    private static ?self $instance = null;

    /**
     * @var null|OptionsResolver
     */
    private static ?OptionsResolver $options_resolver = null;

    /**
     * @return array<string, mixed>|mixed
     */
    public static function get_defaults(?string $key = null): mixed
    {
        static $defaults = null;

        if (null === $defaults) {
            $defaults = [
                'org_display_name' => self::safe_get_bloginfo_name(),
                'field_to_match_to_upn' => 'email',
                'default_wp_role' => null,
                'enable_auto_provisioning' => false,
                'match_on_upn_alias' => false,
                'enable_auto_forward_to_aad' => false,
                'enable_aad_group_to_wp_role' => false,
                'redirect_uri' => self::safe_wp_login_url(),
                'logout_redirect_uri' => self::safe_wp_login_url(),
                'openid_configuration_endpoint' => self::DEFAULT_OPENID_CONFIGURATION_ENDPOINT,
            ];
        }

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
                ->default(self::safe_wp_login_url());

            self::$options_resolver->define('org_display_name')
                ->allowedTypes('string')
                ->default(self::safe_get_bloginfo_name());

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
                ->default(self::DEFAULT_OPENID_CONFIGURATION_ENDPOINT);

            self::$options_resolver->define('authorization_endpoint')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('token_endpoint')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('jwks_uri')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('issuer')
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

            self::$options_resolver->define('custom_scope')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('role_map')
                ->allowedTypes('array')
                ->default([]);

            self::$options_resolver->define('tenantRestrictionMode')
                ->allowedTypes('string')
                ->default('none')
                ->allowedValues('none', 'single', 'multi');

            self::$options_resolver->define('expected_tenant_id')
                ->allowedTypes('string')
                ->default('');

            self::$options_resolver->define('allowed_tenant_ids')
                ->allowedTypes('array')
                ->default([]);

            self::$options_resolver->define('allowed_redirect_domains')
                ->allowedTypes('array')
                ->default([]);

            self::$options_resolver->define('block_external_redirects')
                ->allowedTypes('bool')
                ->default(false);
        }

        return self::$options_resolver;
    }

    public static function init(): self
    {
        $instance = self::get_instance();

        $plugin_settings = get_option('aadsso_settings');
        if (\is_array($plugin_settings) && !empty($plugin_settings)) {
            // @var array<string, mixed> $plugin_settings
            $instance->load_settings($plugin_settings);
        }

        $openid_configuration = self::get_cached_openid_configuration();

        if (\is_array($openid_configuration) && !empty($openid_configuration)) {
            $filtered_config = self::filter_to_known_settings($openid_configuration);
            if (!empty($filtered_config)) {
                $instance->load_settings($filtered_config);
            }
        }

        return $instance;
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

            return $response->getBody()->getContents();
        } catch (Throwable $e) {
            AADSSO_Logger::log_error(
                'Failed to fetch remote contents: ' . $e->getMessage()
            );

            return '';
        }
    }

    /**
     * @param array<string, mixed> $settings
     */
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
                        $group_id_trimmed = \is_string($group_id) ? mb_trim(sanitize_text_field($group_id)) : '';
                        $role_slug_sanitized = \is_string($role_slug) ? sanitize_text_field($role_slug) : '';
                        if (!empty($group_id_trimmed) && !isset($settings['aad_group_to_wp_role_map'][$group_id_trimmed])) {
                            $settings['aad_group_to_wp_role_map'][$group_id_trimmed] = $role_slug_sanitized;
                        }
                    }
                } else {
                    $group_ids = \is_string($group_ids_list) ? explode(',', $group_ids_list) : [];
                    if (!empty($group_ids)) {
                        foreach ($group_ids as $group_id) {
                            $group_id_trimmed = mb_trim(sanitize_text_field($group_id));
                            $role_slug_sanitized = sanitize_text_field($role_slug);
                            if (!empty($group_id_trimmed)
                                && !isset($settings['aad_group_to_wp_role_map'][$group_id_trimmed])
                            ) {
                                $settings['aad_group_to_wp_role_map'][$group_id_trimmed] = $role_slug_sanitized;
                            }
                        }
                    }
                }
            }
        }

        try {
            /** @var array<string, mixed> $resolved_settings */
            $resolved_settings = self::get_options_resolver()->resolve($settings);
            foreach ($resolved_settings as $key => $value) {
                if (property_exists($this, $key)) {
                    $this->{$key} = self::sanitize_setting($key, $value);
                }
            }
        } catch (Throwable $e) {
            AADSSO_Logger::log_exception($e, 'Failed to resolve settings with OptionsResolver');
        }

        return $this;
    }

    /**
     * Invalidate the cached OpenID configuration.
     * Should be called on plugin activation/upgrade to ensure fresh discovery.
     * Uses WordPress transients for activation-hook compatibility.
     */
    public static function invalidate_openid_configuration_cache(): void
    {
        $cache_key = 'aadsso_openid_configuration';

        // Use WordPress transient as primary (works during activation hooks)
        if (\function_exists('delete_transient')) {
            delete_transient($cache_key);
        }

        // Also attempt PSR-16 cache cleanup if available
        try {
            $cache = AADSSO_Logger::get_cache();
            $cache->delete($cache_key);
        } catch (Throwable) {
            // Silently fail - transient deletion above is primary
        }
    }

    /**
     * Validate a redirect URL against configured security policies.
     *
     * This provides defense-in-depth against open redirect attacks.
     *
     * Security checks (in order):
     * 1. If block_external_redirects is enabled, only allow same-site redirects
     * 2. If allowed_redirect_domains is configured, only allow redirects to those domains
     * 3. Falls back to wp_safe_redirect() which validates against allowed hosts
     *
     * @param string $redirect_url The URL to validate
     *
     * @return string The validated URL, or empty string if not allowed
     */
    public static function validate_redirect_url(string $redirect_url): string
    {
        // Empty URL is always allowed (will use default)
        if ('' === $redirect_url) {
            return '';
        }

        // Reject protocol-relative URLs (//host, /\host, ///host)
        // These are external redirects disguised as relative URLs
        // e.g., //evil.com or /\evil.com or ///evil.com
        if (0 === strncmp($redirect_url, '//', 2) || 0 === strncmp($redirect_url, '/\\', 2)) {
            AADSSO_Logger::log_warning(
                \sprintf('Protocol-relative redirect blocked: %s', $redirect_url)
            );

            return '';
        }

        // Parse the redirect URL
        $parsed = parse_url($redirect_url);

        // If parse failed or no host, it's likely a relative URL - allow it
        if (false === $parsed || !isset($parsed['host'])) {
            // Relative URLs are safe within the same site
            // Accept: /path, ?query=string, #fragment, /path?query#fragment
            // Reject any malformed URL (e.g., multiple leading slashes caught above)
            $first_char = $redirect_url[0] ?? '';
            if ('/' === $first_char || '?' === $first_char || '#' === $first_char) {
                return $redirect_url;
            }

            return '';
        }

        $redirect_host = mb_strtolower($parsed['host']);

        // Check block_external_redirects first
        if (!empty(self::get_instance()->block_external_redirects)) {
            // Use home_url() for public-facing URL validation
            // home_url() returns the URL to the home location of the site as set
            // in Settings > General, which is appropriate for redirect validation
            //
            // Fall back to empty string if home_url() is not available
            // (e.g., during bootstrap or in some test environments)
            if (\function_exists('home_url')) {
                $site_host = mb_strtolower(parse_url(home_url(), \PHP_URL_HOST) ?: '');
            } else {
                $site_host = '';
            }

            if ('' !== $site_host && $redirect_host !== $site_host) {
                AADSSO_Logger::log_warning(
                    \sprintf('External redirect blocked: %s (only %s allowed)', $redirect_url, $site_host)
                );

                return '';
            }
        }

        // Check allowed_redirect_domains
        // Note: allowed_redirect_domains are stored lowercase during sanitization
        $allowed_domains = self::get_instance()->allowed_redirect_domains;
        if (!empty($allowed_domains)) {
            $redirect_lower = mb_strtolower($redirect_host);

            // Check exact match or subdomain match
            $is_allowed = false;
            foreach ($allowed_domains as $allowed) {
                // Exact match (both already lowercase)
                if ($redirect_lower === $allowed) {
                    $is_allowed = true;

                    break;
                }

                // Subdomain match (example.com allows sub.example.com)
                if (
                    mb_strlen($redirect_lower) > mb_strlen($allowed) + 1
                    && str_ends_with($redirect_lower, '.' . $allowed)
                ) {
                    $is_allowed = true;

                    break;
                }
            }

            if (!$is_allowed) {
                AADSSO_Logger::log_warning(
                    \sprintf('Redirect to untrusted domain blocked: %s (not in allowlist)', $redirect_url)
                );

                return '';
            }
        }

        return $redirect_url;
    }

    /**
     * Public API for sanitizing option values.
     *
     * This provides a testable public interface for sanitization logic.
     *
     * @param string $key   The option key to sanitize
     * @param mixed  $value The raw option value
     *
     * @return mixed The sanitized value
     */
    public static function sanitize_option(string $key, mixed $value): mixed
    {
        return self::sanitize_setting($key, $value);
    }

    /**
     * Safely get blog name, with fallback for when WordPress is not fully initialized.
     */
    private static function safe_get_bloginfo_name(): string
    {
        if (\function_exists('get_bloginfo')) {
            return (string) get_bloginfo('name');
        }

        return '';
    }

    /**
     * Safely get WordPress login URL, with fallback for when WordPress is not fully initialized.
     */
    private static function safe_wp_login_url(): string
    {
        if (\function_exists('wp_login_url')) {
            return (string) wp_login_url();
        }

        return '';
    }

    /**
     * @param array<string, mixed> $settings
     *
     * @return array<string, mixed>
     */
    private static function filter_to_known_settings(array $settings): array
    {
        $resolver = self::get_options_resolver();
        $defined_options = array_keys($resolver->resolve([]));

        /** @var array<string, mixed> */
        $filtered = array_filter(
            $settings,
            static fn ($value, string $key): bool => \in_array($key, $defined_options, true),
            \ARRAY_FILTER_USE_BOTH
        );

        // Ensure the result has string keys
        // @var array<string, mixed>
        return array_combine(
            array_map('strval', array_keys($filtered)),
            array_values($filtered)
        ) ?: $filtered;
    }

    /**
     * @return array<string, mixed>|false
     */
    private static function get_cached_openid_configuration(): array|false
    {
        $force_reload = isset($_GET['aadsso_reload_openid_config']);

        if ($force_reload && current_user_can('manage_options') && check_admin_referer('aadsso_reload_openid_config')) {
            $config = self::fetch_openid_configuration();

            if (\is_array($config) && !empty($config)) {
                try {
                    $cache = AADSSO_Logger::get_cache();
                    $cache->set('aadsso_openid_configuration', $config, 3600);
                } catch (Throwable $e) {
                    AADSSO_Logger::log_exception($e, 'Cache write failed for OpenID configuration');
                }
            }

            return $config;
        }

        $cache = AADSSO_Logger::get_cache();

        try {
            $cached = $cache->get('aadsso_openid_configuration');
            if (\is_array($cached) && !empty($cached)) {
                // @var array<string, mixed>
                return $cached;
            }
        } catch (Throwable $e) {
            AADSSO_Logger::log_exception($e, 'Cache read failed for OpenID configuration');
        }

        $config = self::fetch_openid_configuration();

        if (\is_array($config) && !empty($config)) {
            try {
                $cache->set('aadsso_openid_configuration', $config, 3600);
            } catch (Throwable $e) {
                AADSSO_Logger::log_exception($e, 'Cache write failed for OpenID configuration');
            }
        }

        return $config;
    }

    /**
     * @return array<string, mixed>|false
     */
    private static function fetch_openid_configuration(): array|false
    {
        $instance = self::get_instance();
        $remote_response = self::get_remote_contents(
            esc_url_raw($instance->openid_configuration_endpoint)
        );

        if (!empty($remote_response)) {
            $openid_configuration = json_decode($remote_response, true);

            if (\JSON_ERROR_NONE !== json_last_error()) {
                AADSSO_Logger::log_error('OpenID configuration JSON decode error: ' . json_last_error_msg());

                return false;
            }

            if (\is_array($openid_configuration) && !empty($openid_configuration)) {
                // @var array<string, mixed>
                return $openid_configuration;
            }
        }

        return false;
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
            $url_value = \is_string($value) ? $value : '';

            return esc_url_raw($url_value);
        }

        return match ($key) {
            'client_id' => sanitize_text_field(\is_string($value) ? $value : ''),
            'client_secret' => \is_string($value) ? $value : '',
            'issuer' => sanitize_text_field(\is_string($value) ? $value : ''),
            'org_display_name', 'org_domain_hint',
            'field_to_match_to_upn', 'default_wp_role',
            'graph_version', 'custom_scope' => sanitize_text_field(\is_string($value) ? $value : ''),
            'tenantRestrictionMode' => \is_string($value) && \in_array($value, ['none', 'single', 'multi'], true) ? $value : 'none',
            'expected_tenant_id' => self::sanitize_tenant_id($value),
            'allowed_tenant_ids' => self::sanitize_tenant_ids($value),
            'allowed_redirect_domains' => self::sanitize_redirect_domains($value),
            'block_external_redirects',
            'match_on_upn_alias',
            'enable_auto_provisioning',
            'enable_auto_forward_to_aad',
            'enable_aad_group_to_wp_role',
            'enable_full_logout' => (bool) $value,
            'aad_group_to_wp_role_map' => \is_array($value) ? $value : [],
            default => $value,
        };
    }

    /**
     * Sanitize and validate a single tenant ID.
     *
     * @param mixed $value
     *
     * @return string
     */
    private static function sanitize_tenant_id(mixed $value): string
    {
        if (!\is_string($value)) {
            return '';
        }

        $trimmed = mb_trim($value);

        // Empty string is valid (allows clearing the setting)
        if ('' === $trimmed) {
            return '';
        }

        // Validate GUID format: 8-4-4-4-12 hex characters
        if (1 !== preg_match('#^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$#i', $trimmed)) {
            return '';
        }

        return $trimmed;
    }

    /**
     * Sanitize and validate tenant IDs.
     *
     * Handles both array and newline-separated string input for flexibility.
     * String input is parsed and each line is treated as a separate tenant ID.
     *
     * @param mixed $value Array of tenant IDs or newline-separated string
     *
     * @return list<string>
     */
    private static function sanitize_tenant_ids(mixed $value): array
    {
        // Handle newline-separated string input (from UI textarea)
        if (\is_string($value)) {
            $lines = array_filter(
                array_map('trim', explode("\n", $value))
            );
            $value = $lines;
        }

        if (!\is_array($value)) {
            return [];
        }

        // @var list<string> $sanitized
        return array_filter(
            array_map(
                static function (mixed $id): string {
                    if (!\is_string($id)) {
                        return '';
                    }
                    // Validate GUID format (tenant ID should be a GUID)
                    $trimmed = mb_trim($id);
                    // GUID format: 8-4-4-4-12 hex characters
                    if (preg_match('#^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$#i', $trimmed)) {
                        return $trimmed;
                    }

                    return '';
                },
                $value
            )
        );
    }

    /**
     * Sanitize and validate allowed redirect domains.
     *
     * Validates each domain to ensure it follows proper hostname format.
     * Accepts both single-label hostnames (e.g., "localhost") and multi-label
     * domain names (e.g., "example.com", "sub.example.org").
     *
     * Handles both array and newline-separated string input for flexibility.
     *
     * @param mixed $value Array of domains or newline-separated string
     *
     * @return list<string>
     */
    private static function sanitize_redirect_domains(mixed $value): array
    {
        // Handle newline-separated string input (from UI textarea)
        if (\is_string($value)) {
            $lines = array_filter(
                array_map('trim', explode("\n", $value))
            );
            $value = $lines;
        }

        if (!\is_array($value)) {
            return [];
        }

        // @var list<string> $sanitized
        return array_filter(
            array_map(
                static function (mixed $domain): string {
                    if (!\is_string($domain)) {
                        return '';
                    }

                    $trimmed = mb_trim($domain);

                    // Empty strings are filtered out
                    if ('' === $trimmed) {
                        return '';
                    }

                    // Remove protocol if present (normalize input)
                    $trimmed = preg_replace('#^https?://#', '', $trimmed);

                    // Remove trailing slash
                    $trimmed = mb_rtrim($trimmed, '/');

                    // Validate hostname format:
                    // - Must not be empty after removing protocol/slash
                    // - Must contain only valid hostname characters
                    // - Supports single-label (localhost, devserver) and multi-label (example.com)
                    //
                    // Valid patterns:
                    //   localhost
                    //   devserver
                    //   example.com
                    //   sub.example.com
                    //   my-server.local
                    //
                    // Invalid:
                    //   (empty string)
                    //   host-
                    //   -host
                    //   contains spaces
                    if (
                        '' === $trimmed
                        || !preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i', $trimmed)
                    ) {
                        return '';
                    }

                    // Normalize to lowercase for consistent comparison
                    return mb_strtolower($trimmed);
                },
                $value
            )
        );
    }
}

class_alias(Settings::class, 'AADSSO_Settings');
