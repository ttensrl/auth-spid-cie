<?php
/**
 * Fired when the plugin is deleted from the Plugins screen.
 * Removes options and cached data. Keys, certificates and registered metadata live in the plugin's
 * data/ folder (default), which WordPress deletes together with the plugin: they are LOST, and a
 * certificate registered with AgID/CIE must be redone. The admin page warns about it; download
 * the certificate and the registered metadata first. With WPSPID_PRIVATE_DIR they stay where they are.
 */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'wpspid_options' );
delete_option( 'wpspid_production' );
delete_transient( 'wpspid_registry_spid' );
delete_transient( 'wpspid_cie_prod' );
delete_transient( 'wpspid_cie_test' );
delete_transient( 'wpspid_probe' );
delete_option( 'wpspid_preserved_path' );
delete_option( 'wpspid_restore_failed' );

global $wpdb;
// Pending requests and replay markers (transients and their timeouts).
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_wpspid\_%' OR option_name LIKE '\_transient\_timeout\_wpspid\_%'" ); // phpcs:ignore WordPress.DB
