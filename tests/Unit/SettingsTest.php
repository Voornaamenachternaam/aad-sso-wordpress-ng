<?php

declare(strict_types=1);

namespace AADSSO\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Settings unit tests.
 *
 * @internal
 */
class SettingsTest extends TestCase
{
    /**
     * Set up before each test.
     */
    protected function setUp(): void
    {
        parent::setUp();
        $reflection = new \ReflectionClass(\AADSSO_Settings::class);
        $property = $reflection->getProperty('instance');
        $property->setAccessible(true);
        $property->setValue(null, null);

        $resolver_prop = $reflection->getProperty('options_resolver');
        $resolver_prop->setAccessible(true);
        $resolver_prop->setValue(null, null);
    }

    /**
     * Test settings class exists.
     */
    public function testSettingsClassExists(): void
    {
        $this->assertTrue(class_exists('AADSSO_Settings'));
    }

    /**
     * Test get_instance returns singleton.
     */
    public function testGetInstanceReturnsSingleton(): void
    {
        $instance1 = \AADSSO_Settings::get_instance();
        $instance2 = \AADSSO_Settings::get_instance();
        $this->assertSame($instance1, $instance2);
    }

    /**
     * Test get_defaults returns array.
     */
    public function testGetDefaultsReturnsArray(): void
    {
        $defaults = \AADSSO_Settings::get_defaults();
        $this->assertIsArray($defaults);
    }

    /**
     * Test get_defaults with key returns value.
     */
    public function testGetDefaultsWithKeyReturnsValue(): void
    {
        $default = \AADSSO_Settings::get_defaults('field_to_match_to_upn');
        $this->assertEquals('email', $default);
    }

    /**
     * Test load_settings returns self.
     */
    public function testLoadSettingsReturnsSelf(): void
    {
        $settings = \AADSSO_Settings::get_instance();
        $result = $settings->load_settings([]);
        $this->assertSame($settings, $result);
    }

    /**
     * Test load_settings with empty array does not throw.
     */
    public function testLoadSettingsWithEmptyArrayDoesNotThrow(): void
    {
        $this->expectNotToPerformAssertions();
        $settings = \AADSSO_Settings::get_instance();
        $settings->load_settings([]);
    }

    /**
     * Test load_settings with null does not throw.
     */
    public function testLoadSettingsWithNullDoesNotThrow(): void
    {
        $this->expectNotToPerformAssertions();
        $settings = \AADSSO_Settings::get_instance();
        $settings->load_settings(null);
    }

    /**
     * Test get_options_resolver returns options resolver.
     */
    public function testGetOptionsResolverReturnsOptionsResolver(): void
    {
        $resolver = \AADSSO_Settings::get_options_resolver();
        $this->assertInstanceOf(\Symfony\Component\OptionsResolver\OptionsResolver::class, $resolver);
    }

    /**
     * Test load_settings uses options resolver.
     */
    public function testLoadSettingsUsesOptionsResolver(): void
    {
        $settings = \AADSSO_Settings::get_instance();

        /** @var array<string, mixed> $input_settings */
        $input_settings = [
            'client_id' => 'test-client-id',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://example.com/callback',
            'org_display_name' => 'Test Organization',
            'field_to_match_to_upn' => 'email',
            'enable_auto_provisioning' => true,
        ];

        $settings->load_settings($input_settings);

        $this->assertEquals('test-client-id', $settings->client_id);
        $this->assertEquals('test-secret', $settings->client_secret);
        $this->assertEquals('https://example.com/callback', $settings->redirect_uri);
        $this->assertEquals('Test Organization', $settings->org_display_name);
        $this->assertEquals('email', $settings->field_to_match_to_upn);
        $this->assertTrue($settings->enable_auto_provisioning);
    }

    /**
     * Test load_settings with role_map converts to aad_group_to_wp_role_map.
     */
    public function testLoadSettingsWithRoleMapConvertsToAadGroupToWpRoleMap(): void
    {
        $settings = \AADSSO_Settings::get_instance();

        /** @var array<string, mixed> $input_settings */
        $input_settings = [
            'client_id' => 'test-client-id',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://example.com/callback',
            'role_map' => [
                'administrator' => 'group-id-1,group-id-2',
                'editor' => 'group-id-3',
            ],
        ];

        $settings->load_settings($input_settings);

        /** @var array<string, string> $expected_map */
        $expected_map = [
            'group-id-1' => 'administrator',
            'group-id-2' => 'administrator',
            'group-id-3' => 'editor',
        ];

        $this->assertEquals($expected_map, $settings->aad_group_to_wp_role_map);
    }

    /**
     * Test options resolver validates allowed values.
     */
    public function testOptionsResolverValidatesAllowedValues(): void
    {
        $resolver = \AADSSO_Settings::get_options_resolver();

        $resolved = $resolver->resolve([
            'client_id' => 'test',
            'client_secret' => 'test',
            'redirect_uri' => 'https://example.com',
            'field_to_match_to_upn' => 'email',
        ]);

        $this->assertEquals('email', $resolved['field_to_match_to_upn']);
    }

    /**
     * Test options resolver applies defaults.
     */
    public function testOptionsResolverAppliesDefaults(): void
    {
        $resolver = \AADSSO_Settings::get_options_resolver();

        $resolved = $resolver->resolve([
            'client_id' => 'test',
            'client_secret' => 'test',
            'redirect_uri' => 'https://example.com',
        ]);

        $this->assertFalse($resolved['enable_auto_provisioning']);
        $this->assertEquals('v1.0', $resolved['graph_version']);
        $this->assertEquals('https://graph.microsoft.com', $resolved['graph_endpoint']);
    }

    /**
     * Test options resolver allows only email or login for field to match.
     */
    public function testOptionsResolverAllowsOnlyEmailOrLoginForFieldToMatch(): void
    {
        $resolver = \AADSSO_Settings::get_options_resolver();

        $resolved = $resolver->resolve([
            'client_id' => 'test',
            'client_secret' => 'test',
            'redirect_uri' => 'https://example.com',
            'field_to_match_to_upn' => 'login',
        ]);
        $this->assertEquals('login', $resolved['field_to_match_to_upn']);
    }

    /**
     * Test settings properties have correct defaults.
     */
    public function testSettingsPropertiesHaveCorrectDefaults(): void
    {
        $settings = \AADSSO_Settings::get_instance();

        $this->assertEquals('', $settings->client_id);
        $this->assertEquals('', $settings->client_secret);
        $this->assertEquals('', $settings->redirect_uri);
        $this->assertEquals('', $settings->authorization_endpoint);
        $this->assertEquals('', $settings->token_endpoint);
        $this->assertEquals('', $settings->jwks_uri);
        $this->assertEquals('', $settings->end_session_endpoint);
        $this->assertFalse($settings->enable_auto_provisioning);
        $this->assertFalse($settings->enable_auto_forward_to_aad);
        $this->assertFalse($settings->enable_aad_group_to_wp_role);
        $this->assertEquals([], $settings->aad_group_to_wp_role_map);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // Redirect Security Tests - F-06 Implementation
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Test validate_redirect_url returns empty string for empty input.
     */
    public function testValidateRedirectUrlReturnsEmptyForEmptyInput(): void
    {
        $result = \AADSSO_Settings::validate_redirect_url('');
        $this->assertEquals('', $result);
    }

    /**
     * Test validate_redirect_url allows relative URLs.
     */
    public function testValidateRedirectUrlAllowsRelativeUrls(): void
    {
        // Path-only URLs
        $result = \AADSSO_Settings::validate_redirect_url('/wp-admin/');
        $this->assertEquals('/wp-admin/', $result);

        $result2 = \AADSSO_Settings::validate_redirect_url('/dashboard');
        $this->assertEquals('/dashboard', $result2);

        // Query string only URLs
        $result3 = \AADSSO_Settings::validate_redirect_url('?page=123');
        $this->assertEquals('?page=123', $result3);

        $result4 = \AADSSO_Settings::validate_redirect_url('?redirect=admin');
        $this->assertEquals('?redirect=admin', $result4);

        // Fragment-only URLs
        $result5 = \AADSSO_Settings::validate_redirect_url('#section');
        $this->assertEquals('#section', $result5);
    }

    /**
     * Test validate_redirect_url rejects external redirects when block_external_redirects is true.
     *
     * Note: This test requires WordPress functions (home_url()) to be available.
     * Skip when running outside WordPress environment.
     */
    public function testValidateRedirectUrlRejectsExternalWhenBlocked(): void
    {
        // Skip if home_url() is not available (outside WordPress environment)
        if (!\function_exists('home_url')) {
            $this->markTestSkipped('home_url() not available outside WordPress environment');
        }

        // Enable external redirect blocking
        $settings = \AADSSO_Settings::get_instance();
        $original_block_setting = $settings->block_external_redirects;
        $settings->block_external_redirects = true;

        // Test external URL is rejected
        $result = \AADSSO_Settings::validate_redirect_url('https://evil.com/steal?redirect=bank');
        $this->assertEquals('', $result, 'External redirect should be blocked when block_external_redirects is true');

        // Test relative URLs are always allowed
        $result2 = \AADSSO_Settings::validate_redirect_url('/wp-admin/');
        $this->assertEquals('/wp-admin/', $result2, 'Relative URLs should always be allowed');

        // Restore original setting
        $settings->block_external_redirects = $original_block_setting;
    }

    /**
     * Test sanitize_redirect_domains handles invalid input through public sanitize() API.
     */
    public function testSanitizeRedirectDomainsHandlesInvalidInput(): void
    {
        // Test null input via public sanitize API
        $result = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', null);
        $this->assertEquals([], $result);

        // Test non-string, non-array input
        $result2 = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', 123);
        $this->assertEquals([], $result2);
    }

    /**
     * Test sanitize_redirect_domains strips protocols and trailing slashes.
     */
    public function testSanitizeRedirectDomainsStripsProtocolsAndSlashes(): void
    {
        // Single domain with protocol and trailing slash
        $result = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', 'https://Example.COM/');
        $this->assertContains('example.com', $result);
        $this->assertNotContains('Example.COM', $result);

        // Single domain without path (path would cause validation failure)
        $result2 = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', 'http://EXAMPLE.ORG');
        $this->assertContains('example.org', $result2);
    }

    /**
     * Test sanitize_redirect_domains accepts single-label hostnames like localhost.
     */
    public function testSanitizeRedirectDomainsAcceptsSingleLabelHostnames(): void
    {
        // Single label hostnames should now be accepted
        $result = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', 'localhost');
        $this->assertContains('localhost', $result);

        $result2 = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', 'devserver');
        $this->assertContains('devserver', $result2);

        $result3 = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', 'my-server');
        $this->assertContains('my-server', $result3);
    }

    /**
     * Test sanitize_redirect_domains rejects truly invalid hostnames.
     */
    public function testSanitizeRedirectDomainsRejectsInvalidHostnames(): void
    {
        // Empty string
        $result = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', '');
        $this->assertEquals([], $result);

        // Only whitespace
        $result2 = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', '   ');
        $this->assertEquals([], $result2);

        // Contains spaces
        $result3 = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', 'has space.com');
        $this->assertEquals([], $result3);

        // Starts with dash
        $result4 = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', '-startswithdash.com');
        $this->assertEquals([], $result4);

        // Ends with dash
        $result5 = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', 'endswithdash-.com');
        $this->assertEquals([], $result5);
    }

    /**
     * Test sanitize_redirect_domains handles newline-separated input.
     */
    public function testSanitizeRedirectDomainsHandlesNewlineSeparatedInput(): void
    {
        $input = "example.com\nexample.org\nsub.example.net";
        $result = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', $input);

        $this->assertCount(3, $result);
        $this->assertContains('example.com', $result);
        $this->assertContains('example.org', $result);
        $this->assertContains('sub.example.net', $result);
    }

    /**
     * Test sanitize_redirect_domains filters out invalid entries.
     */
    public function testSanitizeRedirectDomainsFiltersInvalidEntries(): void
    {
        // Mix of valid and invalid entries - only valid ones should pass
        // Note: localhost is now valid (single-label hostnames are allowed)
        $input = [
            'valid.example.com',
            'localhost',         // Now valid!
            '',
            '   ',               // Now invalid (empty after trim)
            'https://another-valid.com/',
        ];
        $result = \AADSSO_Settings::sanitize_option('allowed_redirect_domains', $input);

        // 3 valid: valid.example.com, localhost, another-valid.com
        $this->assertCount(3, $result);
        $this->assertContains('valid.example.com', $result);
        $this->assertContains('localhost', $result);
        $this->assertContains('another-valid.com', $result);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // End Redirect Security Tests
    // ══════════════════════════════════════════════════════════════════════════

    // ══════════════════════════════════════════════════════════════════════════
    // OpenID Connect Discovery v2.0 & Validation Tests - Item 1 Implementation
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Test default OpenID configuration endpoint is v2.0.
     */
    public function testDefaultOpenidConfigurationEndpointIsV2(): void
    {
        $this->assertEquals(
            'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
            \AADSSO_Settings::DEFAULT_OPENID_CONFIGURATION_ENDPOINT
        );
    }

    /**
     * Test valid Entra v2.0 organizations discovery configuration passes validation.
     */
    public function testValidateOpenidConfigurationWithValidOrganizationsV2(): void
    {
        $validConfig = [
            'authorization_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.microsoftonline.com/organizations/discovery/v2.0/keys',
            'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
            'response_types_supported' => ['code', 'id_token', 'code id_token'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertTrue(\AADSSO_Settings::validate_openid_configuration($validConfig));
    }

    /**
     * Test valid Entra v2.0 common discovery configuration passes validation.
     */
    public function testValidateOpenidConfigurationWithValidCommonV2(): void
    {
        $validConfig = [
            'authorization_endpoint' => 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
            'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertTrue(\AADSSO_Settings::validate_openid_configuration($validConfig));
    }

    /**
     * Test valid single-tenant v2.0 discovery configuration passes validation when tenant matches.
     */
    public function testValidateOpenidConfigurationWithValidSingleTenantV2(): void
    {
        $tenantId = '11111111-2222-3333-4444-555555555555';
        $settings = \AADSSO_Settings::get_instance();
        $settings->tenantRestrictionMode = 'single';
        $settings->expected_tenant_id = $tenantId;

        $validConfig = [
            'authorization_endpoint' => 'https://login.microsoftonline.com/' . $tenantId . '/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.microsoftonline.com/' . $tenantId . '/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.microsoftonline.com/' . $tenantId . '/discovery/v2.0/keys',
            'issuer' => 'https://login.microsoftonline.com/' . $tenantId . '/v2.0',
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertTrue(\AADSSO_Settings::validate_openid_configuration($validConfig, $settings));
    }

    /**
     * Test valid US Government sovereign cloud discovery passes validation.
     */
    public function testValidateOpenidConfigurationWithValidUsGovernmentSovereignCloud(): void
    {
        $validConfig = [
            'authorization_endpoint' => 'https://login.microsoftonline.us/organizations/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.microsoftonline.us/organizations/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.microsoftonline.us/organizations/discovery/v2.0/keys',
            'issuer' => 'https://login.microsoftonline.us/{tenantid}/v2.0',
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertTrue(\AADSSO_Settings::validate_openid_configuration($validConfig));
    }

    /**
     * Test valid China sovereign cloud discovery passes validation.
     */
    public function testValidateOpenidConfigurationWithValidChinaSovereignCloud(): void
    {
        $validConfig = [
            'authorization_endpoint' => 'https://login.chinacloudapi.cn/organizations/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.chinacloudapi.cn/organizations/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.chinacloudapi.cn/organizations/discovery/v2.0/keys',
            'issuer' => 'https://login.chinacloudapi.cn/{tenantid}/v2.0',
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertTrue(\AADSSO_Settings::validate_openid_configuration($validConfig));
    }

    /**
     * Test validation fails when required keys are missing.
     */
    public function testValidateOpenidConfigurationRejectsMissingRequiredKeys(): void
    {
        $invalidConfig = [
            'authorization_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            // jwks_uri missing
            'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertFalse(\AADSSO_Settings::validate_openid_configuration($invalidConfig));
    }

    /**
     * Test validation fails when endpoints are not HTTPS.
     */
    public function testValidateOpenidConfigurationRejectsNonHttps(): void
    {
        $invalidConfig = [
            'authorization_endpoint' => 'http://login.microsoftonline.com/organizations/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.microsoftonline.com/organizations/discovery/v2.0/keys',
            'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertFalse(\AADSSO_Settings::validate_openid_configuration($invalidConfig));
    }

    /**
     * Test validation fails when endpoints are non-v2.
     */
    public function testValidateOpenidConfigurationRejectsNonV2Endpoints(): void
    {
        $invalidConfig = [
            'authorization_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/authorize',
            'token_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/token',
            'jwks_uri' => 'https://login.microsoftonline.com/organizations/discovery/keys',
            'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertFalse(\AADSSO_Settings::validate_openid_configuration($invalidConfig));
    }

    /**
     * Test validation fails when issuer is non-v2.
     */
    public function testValidateOpenidConfigurationRejectsNonV2Issuer(): void
    {
        $invalidConfig = [
            'authorization_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.microsoftonline.com/organizations/discovery/v2.0/keys',
            'issuer' => 'https://login.microsoftonline.com/organizations', // missing /v2.0
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertFalse(\AADSSO_Settings::validate_openid_configuration($invalidConfig));
    }

    /**
     * Test validation fails when code is missing from response_types_supported.
     */
    public function testValidateOpenidConfigurationRejectsMissingCodeResponseType(): void
    {
        $invalidConfig = [
            'authorization_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.microsoftonline.com/organizations/discovery/v2.0/keys',
            'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
            'response_types_supported' => ['id_token'], // missing code
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertFalse(\AADSSO_Settings::validate_openid_configuration($invalidConfig));
    }

    /**
     * Test validation fails when RS256 is missing from id_token_signing_alg_values_supported.
     */
    public function testValidateOpenidConfigurationRejectsMissingRS256Alg(): void
    {
        $invalidConfig = [
            'authorization_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.microsoftonline.com/organizations/discovery/v2.0/keys',
            'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['HS256'], // missing RS256
        ];

        $this->assertFalse(\AADSSO_Settings::validate_openid_configuration($invalidConfig));
    }

    /**
     * Test single tenant mode rejects discovery metadata when tenant ID mismatches expected_tenant_id.
     */
    public function testValidateOpenidConfigurationRejectsSingleTenantMismatch(): void
    {
        $settings = \AADSSO_Settings::get_instance();
        $settings->tenantRestrictionMode = 'single';
        $settings->expected_tenant_id = '11111111-1111-1111-1111-111111111111';

        $mismatchedConfig = [
            'authorization_endpoint' => 'https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/discovery/v2.0/keys',
            'issuer' => 'https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0',
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertFalse(\AADSSO_Settings::validate_openid_configuration($mismatchedConfig, $settings));
    }

    /**
     * Test multi tenant mode rejects discovery metadata when tenant ID is not in allowed_tenant_ids.
     */
    public function testValidateOpenidConfigurationRejectsMultiTenantMismatch(): void
    {
        $settings = \AADSSO_Settings::get_instance();
        $settings->tenantRestrictionMode = 'multi';
        $settings->allowed_tenant_ids = ['11111111-1111-1111-1111-111111111111'];

        $unallowedConfig = [
            'authorization_endpoint' => 'https://login.microsoftonline.com/33333333-3333-3333-3333-333333333333/oauth2/v2.0/authorize',
            'token_endpoint' => 'https://login.microsoftonline.com/33333333-3333-3333-3333-333333333333/oauth2/v2.0/token',
            'jwks_uri' => 'https://login.microsoftonline.com/33333333-3333-3333-3333-333333333333/discovery/v2.0/keys',
            'issuer' => 'https://login.microsoftonline.com/33333333-3333-3333-3333-333333333333/v2.0',
            'response_types_supported' => ['code'],
            'id_token_signing_alg_values_supported' => ['RS256'],
        ];

        $this->assertFalse(\AADSSO_Settings::validate_openid_configuration($unallowedConfig, $settings));
    }

    /**
     * Test legacy discovery endpoint URL migration to v2.0.
     */
    public function testMigrateOpenidEndpointToV2(): void
    {
        // Legacy v1 organizations endpoint
        $migrated1 = \AADSSO_Settings::migrate_openid_endpoint_to_v2('https://login.microsoftonline.com/organizations/.well-known/openid-configuration');
        $this->assertEquals('https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration', $migrated1);

        // Legacy v1 common endpoint
        $migrated2 = \AADSSO_Settings::migrate_openid_endpoint_to_v2('https://login.microsoftonline.com/common/.well-known/openid-configuration');
        $this->assertEquals('https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration', $migrated2);

        // Already v2.0 endpoint remains unchanged
        $v2Endpoint = 'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration';
        $this->assertEquals($v2Endpoint, \AADSSO_Settings::migrate_openid_endpoint_to_v2($v2Endpoint));
    }

    /**
     * Test extract_tenant_from_issuer helper function.
     */
    public function testExtractTenantFromIssuer(): void
    {
        $tenant = \AADSSO_Settings::extract_tenant_from_issuer('https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0');
        $this->assertEquals('11111111-2222-3333-4444-555555555555', $tenant);

        $orgs = \AADSSO_Settings::extract_tenant_from_issuer('https://login.microsoftonline.com/organizations/v2.0');
        $this->assertEquals('organizations', $orgs);
    }
}
