<?php
/**
 * Fired when the plugin is deleted from the Plugins screen.
 *
 * Temporary data (citizen sessions, pending requests, caches) is always removed. The certificate, the
 * private key, the registered metadata and the organization settings are KEPT unless
 * WPSPID_REMOVE_DATA_ON_UNINSTALL is true in wp-config.php: registering again with AgID/CIE is costly.
 * See docs/STORAGE.md.
 */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/includes/Support/Uninstaller.php';
\WpSpidCie\Support\Uninstaller::run();
