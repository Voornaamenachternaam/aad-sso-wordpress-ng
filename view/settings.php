<?php

declare(strict_types=1);

if (!current_user_can('manage_options')) {
    wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'aad-sso-wordpress'));
}
?>

<div class="wrap">
    <h1><?php echo esc_html__('Microsoft Entra ID Settings', 'aad-sso-wordpress'); ?></h1>

    <?php
    $settings_path = \defined('AADSSO_SETTINGS_PATH') && \is_string(AADSSO_SETTINGS_PATH) ? AADSSO_SETTINGS_PATH : '';
if ('' !== $settings_path && file_exists($settings_path)) {
    $reset_url = add_query_arg([
        'page' => 'aadsso_settings',
        'aadsso_nonce' => wp_create_nonce('aadsso_migrate_from_json'),
    ], admin_url('options-general.php'));
    ?>
        <div class="notice notice-info">
            <p>
                <?php
            echo wp_kses(
                \sprintf(
                    // translators: %s: path to settings file
                    __('Old configuration data was found at %s.', 'aad-sso-wordpress'),
                    '<code>' . esc_html($settings_path) . '</code>'
                ),
                ['code' => []]
            );
    ?>
            </p>
            <p><?php esc_html_e('This configuration data can be migrated automatically.', 'aad-sso-wordpress'); ?></p>
            <p><?php esc_html_e('If migration is successful, migration will delete this configuration file.', 'aad-sso-wordpress'); ?></p>
            <p>
                <a href="<?php echo esc_url($reset_url); ?>" class="button button-primary">
                    <?php esc_html_e('Migrate Settings', 'aad-sso-wordpress'); ?>
                </a>
            </p>
        </div>
        <?php
}
?>

    <form method="post" action="options.php" id="aadsso-settings-form">
        <?php settings_fields('aadsso_settings'); ?>
        <?php do_settings_sections('aadsso_settings_page'); ?>
        <?php submit_button(); ?>
    </form>

    <hr />

    <h2><?php esc_html_e('Reset Plugin', 'aad-sso-wordpress'); ?></h2>
    <p><?php esc_html_e('Resetting the plugin will completely remove all settings.', 'aad-sso-wordpress'); ?></p>
    <p>
        <a href="<?php echo esc_url(add_query_arg([
            'page' => 'aadsso_settings',
            'aadsso_nonce' => wp_create_nonce('aadsso_reset_settings'),
        ], admin_url('options-general.php'))); ?>" class="button" onclick="return confirm('<?php esc_attr_e('Are you sure you want to reset all settings? This cannot be undone.', 'aad-sso-wordpress'); ?>')">
            <?php esc_html_e('Reset Settings', 'aad-sso-wordpress'); ?>
        </a>
    </p>
</div>
