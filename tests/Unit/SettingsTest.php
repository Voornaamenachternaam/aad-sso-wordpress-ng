<?php

declare(strict_types=1);

namespace AADSSO\Tests\Unit;

use PHPUnit\Framework\TestCase;

class SettingsTest extends TestCase
{
    public function test_settings_class_exists(): void
    {
        $this->assertTrue(class_exists('AADSSO_Settings'));
    }

    public function test_get_instance_returns_singleton(): void
    {
        $instance1 = AADSSO_Settings::get_instance();
        $instance2 = AADSSO_Settings::get_instance();
        $this->assertSame($instance1, $instance2);
    }

    public function test_get_defaults_returns_array(): void
    {
        $defaults = AADSSO_Settings::get_defaults();
        $this->assertIsArray($defaults);
    }

    public function test_get_defaults_with_key_returns_value(): void
    {
        $default = AADSSO_Settings::get_defaults('field_to_match_to_upn');
        $this->assertEquals('email', $default);
    }

    public function test_load_settings_returns_self(): void
    {
        $settings = AADSSO_Settings::get_instance();
        $result = $settings->load_settings(array());
        $this->assertSame($settings, $result);
    }

    public function test_load_settings_with_empty_array_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        $settings = AADSSO_Settings::get_instance();
        $settings->load_settings(array());
    }

    public function test_load_settings_with_null_does_not_throw(): void
    {
        $this->expectNotToPerformAssertions();
        $settings = AADSSO_Settings::get_instance();
        $settings->load_settings(null);
    }

    public function test_get_options_resolver_returns_options_resolver(): void
    {
        $resolver = AADSSO_Settings::get_options_resolver();
        $this->assertInstanceOf(\Symfony\Component\OptionsResolver\OptionsResolver::class, $resolver);
    }
}