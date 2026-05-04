<?php

declare(strict_types=1);

if (!\defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

delete_option('aadsso_settings');
delete_transient('aadsso_openid_configuration');
