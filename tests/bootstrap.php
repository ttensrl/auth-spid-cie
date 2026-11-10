<?php
// Minimal bootstrap: no WordPress needed for crypto/validator tests.
define( 'ABSPATH', __DIR__ . '/' );
define( 'WPSPID_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
spl_autoload_register( function ( $class ) {
	$prefix = 'WpSpidCie\\';
	if ( 0 !== strncmp( $prefix, $class, strlen( $prefix ) ) ) {
		return;
	}
	$file = WPSPID_PLUGIN_DIR . 'includes/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
	if ( file_exists( $file ) ) {
		require $file;
	}
} );
