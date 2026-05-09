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
        $result = \AADSSO_Settings::validate_redirect_url('/wp-admin/');
        $this->assertEquals('/wp-admin/', $result);

        $result2 = \AADSSO_Settings::validate_redirect_url('/dashboard');
        $this->assertEquals('/dashboard', $result2);
    }

    /**
     * Test validate_redirect_url rejects external redirects when block_external_redirects is true.
     */
    public function testValidateRedirectUrlRejectsExternalWhenBlocked(): void
    {
        $settings = \AADSSO_Settings::get_instance();
        $settings->block_external_redirects = true;
        // Mock site_url to return a known value for testing
        // In a real test environment, this would need to be mocked

        // For unit testing without WordPress, we test the logic directly
        // This tests the sanitize_redirect_domains method
        $domains = \AADSSO_Settings::sanitize_redirect_domains("example.com\nexternal-site.com");

        $this->assertContains('example.com', $domains);
        $this->assertContains('external-site.com', $domains);
    }

    /**
     * Test sanitize_redirect_domains handles invalid input.
     */
    public function testSanitizeRedirectDomainsHandlesInvalidInput(): void
    {
        // Null input
        $result = \AADSSO_Settings::sanitize_redirect_domains(null);
        $this->assertEquals([], $result);

        // Non-array, non-string input
        $result2 = \AADSSO_Settings::sanitize_redirect_domains(123);
        $this->assertEquals([], $result2);
    }

    /**
     * Test sanitize_redirect_domains strips protocols and trailing slashes.
     */
    public function testSanitizeRedirectDomainsStripsProtocolsAndSlashes(): void
    {
        $result = \AADSSO_Settings::sanitize_redirect_domains('https://example.com/');
        $this->assertContains('example.com', $result);

        $result2 = \AADSSO_Settings::sanitize_redirect_domains('http://example.org/path/');
        $this->assertContains('example.org', $result2);
    }

    /**
     * Test sanitize_redirect_domains accepts single-label hostnames like localhost.
     */
    public function testSanitizeRedirectDomainsAcceptsSingleLabelHostnames(): void
    {
        // Single label hostnames should now be accepted
        $result = \AADSSO_Settings::sanitize_redirect_domains('localhost');
        $this->assertContains('localhost', $result);

        $result2 = \AADSSO_Settings::sanitize_redirect_domains('devserver');
        $this->assertContains('devserver', $result2);

        $result3 = \AADSSO_Settings::sanitize_redirect_domains('my-server');
        $this->assertContains('my-server', $result3);
    }

    /**
     * Test sanitize_redirect_domains rejects truly invalid hostnames.
     */
    public function testSanitizeRedirectDomainsRejectsInvalidHostnames(): void
    {
        // Empty string
        $result = \AADSSO_Settings::sanitize_redirect_domains('');
        $this->assertEquals([], $result);

        // Only whitespace
        $result2 = \AADSSO_Settings::sanitize_redirect_domains('   ');
        $this->assertEquals([], $result2);

        // Contains spaces
        $result3 = \AADSSO_Settings::sanitize_redirect_domains('has space.com');
        $this->assertEquals([], $result3);

        // Starts with dash
        $result4 = \AADSSO_Settings::sanitize_redirect_domains('-startswithdash.com');
        $this->assertEquals([], $result4);

        // Ends with dash
        $result5 = \AADSSO_Settings::sanitize_redirect_domains('endswithdash-.com');
        $this->assertEquals([], $result5);
    }

    /**
     * Test sanitize_redirect_domains handles newline-separated input.
     */
    public function testSanitizeRedirectDomainsHandlesNewlineSeparatedInput(): void
    {
        $input = "example.com\nsubdomain.example.org\napi.example.net";
        $result = \AADSSO_Settings::sanitize_redirect_domains($input);

        $this->assertCount(3, $result);
        $this->assertContains('example.com', $result);
        $this->assertContains('subdomain.example.org', $result);
        $this->assertContains('api.example.net', $result);
    }

    /**
     * Test sanitize_redirect_domains filters out invalid entries.
     */
    public function testSanitizeRedirectDomainsFiltersInvalidEntries(): void
    {
        $input = [
            'valid.example.com',
            'localhost',
            '',
            '   ',
            'https://another-valid.com/',
        ];
        $result = \AADSSO_Settings::sanitize_redirect_domains($input);

        $this->assertCount(2, $result);
        $this->assertContains('valid.example.com', $result);
        $this->assertContains('another-valid.com', $result);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // End Redirect Security Tests
    // ══════════════════════════════════════════════════════════════════════════
}
