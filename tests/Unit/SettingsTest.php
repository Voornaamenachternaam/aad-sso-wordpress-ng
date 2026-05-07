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
}
