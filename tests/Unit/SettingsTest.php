<?php

declare(strict_types=1);

namespace AADSSO\Tests\Unit;

use PHPUnit\Framework\TestCase;

class SettingsTest extends TestCase
{
    protected function setUp(): void
    {
        // Reset the singleton instance before each test
        $reflection = new \ReflectionClass(\AADSSO_Settings::class);
        $property = $reflection->getProperty('instance');
        $property->setAccessible(true);
        $property->setValue(null, null);

        // Reset the options resolver
        $resolver_prop = $reflection->getProperty('options_resolver');
        $resolver_prop->setAccessible(true);
        $resolver_prop->setValue(null, null);
    }

    public function test_settings_class_exists(): void
    {
        $this->assertTrue(class_exists('AADSSO_Settings'));
    }

    public function test_get_instance_returns_singleton(): void
    {
        $instance1 = \AADSSO_Settings::get_instance();
        $instance2 = \AADSSO_Settings::get_instance();
        $this->assertSame($instance1, $instance2);
    }

    public function test_get_defaults_returns_array(): void
    {
        $defaults = \AADSSO_Settings::get_defaults();
        $this->assertIsArray($defaults);
    }

    public function test_get_defaults_with_key_returns_value(): void
    {
        $default = \AADSSO_Settings::get_defaults('field_to_match_to_upn');
        $this->assertEquals('email', $default);
    }

    public function test_load_settings_returns_self(): void
    {
        $settings = \AADSSO_Settings::get_instance();
        $result = $settings->load_settings(array());
        $this->assertSame($settings, $result);
    }

    public function test_load_settings_with_empty_array_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        $settings = \AADSSO_Settings::get_instance();
        $settings->load_settings(array());
    }

    public function test_load_settings_with_null_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        $settings = \AADSSO_Settings::get_instance();
        $settings->load_settings(null);
    }

    public function test_get_options_resolver_returns_options_resolver(): void
    {
        $resolver = \AADSSO_Settings::get_options_resolver();
        $this->assertInstanceOf(\Symfony\Component\OptionsResolver\OptionsResolver::class, $resolver);
    }

    public function test_load_settings_uses_options_resolver(): void
    {
        $settings = \AADSSO_Settings::get_instance();

        // Test that load_settings properly resolves settings using OptionsResolver
        $input_settings = array(
            'client_id' => 'test-client-id',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://example.com/callback',
            'org_display_name' => 'Test Organization',
            'field_to_match_to_upn' => 'email',
            'enable_auto_provisioning' => true,
        );

        $settings->load_settings($input_settings);

        $this->assertEquals('test-client-id', $settings->client_id);
        $this->assertEquals('test-secret', $settings->client_secret);
        $this->assertEquals('https://example.com/callback', $settings->redirect_uri);
        $this->assertEquals('Test Organization', $settings->org_display_name);
        $this->assertEquals('email', $settings->field_to_match_to_upn);
        $this->assertTrue($settings->enable_auto_provisioning);
    }

    public function test_load_settings_with_role_map_converts_to_aad_group_to_wp_role_map(): void
    {
        $settings = \AADSSO_Settings::get_instance();

        $input_settings = array(
            'client_id' => 'test-client-id',
            'client_secret' => 'test-secret',
            'redirect_uri' => 'https://example.com/callback',
            'role_map' => array(
                'administrator' => 'group-id-1,group-id-2',
                'editor' => 'group-id-3',
            ),
        );

        $settings->load_settings($input_settings);

        $expected_map = array(
            'group-id-1' => 'administrator',
            'group-id-2' => 'administrator',
            'group-id-3' => 'editor',
        );

        $this->assertEquals($expected_map, $settings->aad_group_to_wp_role_map);
    }

    public function test_options_resolver_validates_allowed_values(): void
    {
        $resolver = \AADSSO_Settings::get_options_resolver();

        // field_to_match_to_upn should only allow 'email' or 'login'
        $resolved = $resolver->resolve(array(
            'client_id' => 'test',
            'client_secret' => 'test',
            'redirect_uri' => 'https://example.com',
            'field_to_match_to_upn' => 'email',
        ));

        $this->assertEquals('email', $resolved['field_to_match_to_upn']);
    }

    public function test_options_resolver_applies_defaults(): void
    {
        $resolver = \AADSSO_Settings::get_options_resolver();

        $resolved = $resolver->resolve(array(
            'client_id' => 'test',
            'client_secret' => 'test',
            'redirect_uri' => 'https://example.com',
        ));

        $this->assertFalse($resolved['enable_auto_provisioning']);
        $this->assertEquals('v1.0', $resolved['graph_version']);
        $this->assertEquals('https://graph.microsoft.com', $resolved['graph_endpoint']);
    }
}