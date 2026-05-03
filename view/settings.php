<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap">
    <h1><?php echo esc_html__('Single Sign-on with Microsoft Entra ID', 'aad-sso-wordpress'); ?></h1>
    <p><?php echo esc_html__(
        'Settings for configuring single sign-on with Microsoft Entra ID can be configured here.',
        'aad-sso-wordpress'
    ); ?></p>

    <form method="post" action="options.php">
        <?php
        settings_fields('aadsso_settings');
        do_settings_sections('aadsso_settings_page');
        submit_button();
        ?>
    </form>

    <hr />

    <h2><?php echo esc_html__('Reset Plugin', 'aad-sso-wordpress'); ?></h2>
    <p><?php echo esc_html__(
        'Resetting the plugin will completely remove all settings.',
        'aad-sso-wordpress'
    ); ?></p>
    <p>
        <?php
        printf(
            '<a href="%s" class="button">%s</a> <span class="description">%s</span>',
            esc_url(wp_nonce_url(
                admin_url('options-general.php?page=aadsso_settings'),
                'aadsso_reset_settings',
                'aadsso_nonce'
            )),
            esc_html__('Reset Settings', 'aad-sso-wordpress'),
            esc_html__(
                'Reset the plugin to default settings. Careful, there is no undo for this.',
                'aad-sso-wordpress'
            )
        );
        ?>
    </p>

    <?php if (defined('AADSSO_SETTINGS_PATH') && file_exists(AADSSO_SETTINGS_PATH)): ?>
        <hr />

        <h2><?php echo esc_html__('Migrate Legacy Settings', 'aad-sso-wordpress'); ?></h2>
        <p>
            <?php
            printf(
                esc_html__('Old configuration data was found at %s.', 'aad-sso-wordpress'),
                '<code>' . esc_html(AADSSO_SETTINGS_PATH) . '</code>'
            );
            ?>
            <?php echo esc_html__(
                'This configuration data can be migrated automatically.',
                'aad-sso-wordpress'
            ); ?>
        </p>
        <p>
            <?php
            printf(
                esc_html__('Delete the file at %s to hide this migration utility.', 'aad-sso-wordpress'),
                '<code>' . esc_html(AADSSO_SETTINGS_PATH) . '</code>'
            );
            ?>
        </p>

        <?php if (is_writable(AADSSO_SETTINGS_PATH) && is_writable(dirname(AADSSO_SETTINGS_PATH))): ?>
            <p>
                <?php
                echo esc_html__(
                    'If migration is successful, migration will delete this configuration file, ',
                    'aad-sso-wordpress'
                );
                echo '<code>' . esc_html(AADSSO_SETTINGS_PATH) . '</code>.';
                ?>
            </p>
        <?php else: ?>
            <p>
                <?php
                echo esc_html__(
                    'If migration is successful, migration will be unable to delete the configuration file at ',
                    'aad-sso-wordpress'
                );
                echo '<code>' . esc_html(AADSSO_SETTINGS_PATH) . '</code>. ';
                echo esc_html__(
                    'It is recommended to delete the file after migration.',
                    'aad-sso-wordpress'
                );
                ?>
            </p>
        <?php endif; ?>

        <p>
            <?php
            printf(
                '<a href="%s" class="button">%s</a> <span class="description">%s</span>',
                esc_url(wp_nonce_url(
                    admin_url('options-general.php?page=aadsso_settings'),
                    'aadsso_migrate_from_json',
                    'aadsso_nonce'
                )),
                esc_html__('Migrate Settings', 'aad-sso-wordpress'),
                esc_html__(
                    'Migrate settings from old plugin versions to new configuration. '
                    . 'This will overwrite existing settings! Careful, there is no undo for this.',
                    'aad-sso-wordpress'
                )
            );
            ?>
        </p>
    <?php endif; ?>
</div>