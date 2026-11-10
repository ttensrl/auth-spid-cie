<?php
/**
 * Plugin Name: WP SPID CIE
 * Plugin URI:  https://github.com/luca-terribili/wp-spid-cie
 * Description: Plugin autonomo per l'autenticazione SPID e CIE (Service Provider SAML2) senza dipendenze esterne.
 * Version:     0.1.0
 * Author:      Luca Terribili
 * Author URI:  https://lucaterribili.it
 * License:     GPL-3.0-or-later
 * Text Domain: wp-spid-cie
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

// Define constants.
define( 'WPSPID_VERSION', '0.1.0' );
define( 'WPSPID_PLUGIN_FILE', __FILE__ );
define( 'WPSPID_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPSPID_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

/**
 * Basic PSR-4 Autoloader.
 */
spl_autoload_register( function ( $class ) {
	$prefix = 'WpSpidCie\\';
	$base_dir = WPSPID_PLUGIN_DIR . 'includes/';

	$len = strlen( $prefix );
	if ( strncmp( $prefix, $class, $len ) !== 0 ) {
		return;
	}

	$relative_class = substr( $class, $len );
	$file = $base_dir . str_replace( '\\', '/', $relative_class ) . '.php';

	if ( file_exists( $file ) ) {
		require $file;
	}
} );

/**
 * Check requirements.
 */
function wpspid_check_requirements() {
	$errors = array();

	if ( version_compare( PHP_VERSION, '8.0.0', '<' ) ) {
		$errors[] = sprintf( __( 'Il plugin richiede PHP 8.0 o superiore. La tua versione attuale è %s.', 'wp-spid-cie' ), PHP_VERSION );
	}

	// Estensioni e funzioni OpenSSL (anche quelle disattivate dall'hosting con disable_functions).
	return array_merge( $errors, \WpSpidCie\Support\Requirements::check() );
}

/**
 * Activation hook.
 */
register_activation_hook( __FILE__, function() {
	$errors = wpspid_check_requirements();
	if ( empty( $errors ) ) {
		// Verifica pratica: prova davvero a generare chiavi e certificati (SPID e CIE).
		$probe  = \WpSpidCie\Support\Requirements::probe( true );
		$errors = $probe['errors'];
	}
	if ( ! empty( $errors ) ) {
		deactivate_plugins( plugin_basename( __FILE__ ) );
		wp_die(
			'<p><strong>Il plugin SPID/CIE non può essere attivato su questo server.</strong></p><ul><li>' . implode( '</li><li>', array_map( 'esc_html', $errors ) ) . '</li></ul><p>Chiedi al provider di abilitare l\'estensione PHP openssl e le sue funzioni.</p>',
			'',
			array( 'back_link' => true )
		);
	}

	// Initialize rewrite rules if needed in the future.
	// WpSpidCie\Http\Router::flush_rules();
} );

/**
 * Initialize the plugin.
 */
require_once WPSPID_PLUGIN_DIR . 'includes/Api.php';

add_action( 'plugins_loaded', function() {
	load_plugin_textdomain( 'wp-spid-cie', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );

	if ( ! empty( wpspid_check_requirements() ) ) {
		add_action( 'admin_notices', function() {
			$errors = wpspid_check_requirements();
			echo '<div class="error"><p>' . implode( '</p><p>', array_map( 'esc_html', $errors ) ) . '</p></div>';
		} );
		return;
	}

	WpSpidCie\Plugin::get_instance();
} );
