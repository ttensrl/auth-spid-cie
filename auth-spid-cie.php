<?php
/**
 * Plugin Name: Auth SPID CIE
 * Plugin URI:  https://github.com/ttensrl/auth-spid-cie
 * Description: Standalone SPID and CIE login (SAML 2.0 Service Provider) with no external dependencies.
 * Version:     0.1.0
 * Author:      Luca Terribili
 * Author URI:  https://lucaterribili.it
 * License:     GPL-3.0-or-later
 * Text Domain: auth-spid-cie
 * Domain Path: /languages
 * Requires at least: 6.0
 * Requires PHP: 8.0
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
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
		/* translators: %s: current PHP version. */
		$errors[] = sprintf( __( 'The plugin requires PHP 8.0 or higher. Your current version is %s.', 'auth-spid-cie' ), PHP_VERSION );
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
			'<p><strong>' . esc_html__( 'The SPID/CIE plugin cannot be activated on this server.', 'auth-spid-cie' ) . '</strong></p><ul><li>' . implode( '</li><li>', array_map( 'esc_html', $errors ) ) . '</li></ul><p>' . esc_html__( 'Ask your hosting provider to enable the PHP openssl extension and its functions.', 'auth-spid-cie' ) . '</p>',
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
	// Bundled translations (it_IT); loaded before any message is built.
	load_plugin_textdomain( 'auth-spid-cie', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' ); // phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound -- ships it_IT for installs outside wordpress.org

	if ( ! empty( wpspid_check_requirements() ) ) {
		add_action( 'admin_notices', function() {
			$errors = wpspid_check_requirements();
			echo '<div class="error"><p>' . implode( '</p><p>', array_map( 'esc_html', $errors ) ) . '</p></div>';
		} );
		return;
	}

	WpSpidCie\Plugin::get_instance();
} );
