<?php
// Minimal bootstrap: no WordPress needed for crypto/validator tests.
define( 'ABSPATH', __DIR__ . '/' );
define( 'AUTHSPIDCIE_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
spl_autoload_register( function ( $class ) {
	$prefix = 'AuthSpidCie\\';
	if ( 0 !== strncmp( $prefix, $class, strlen( $prefix ) ) ) {
		return;
	}
	$file = AUTHSPIDCIE_PLUGIN_DIR . 'includes/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
	if ( file_exists( $file ) ) {
		require $file;
	}
} );

// Stub delle funzioni WordPress usate dal plugin (i test girano senza WordPress).
if ( ! function_exists( 'wp_delete_file' ) ) {
	function wp_delete_file( $file ) { @unlink( $file ); }
}
if ( ! function_exists( 'wp_is_writable' ) ) {
	function wp_is_writable( $path ) { return is_writable( $path ); }
}
if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	function wp_strip_all_tags( $s ) { return trim( strip_tags( $s ) ); }
}
if ( ! function_exists( 'wp_parse_url' ) ) {
	function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
}
if ( ! function_exists( 'wp_basename' ) ) {
	function wp_basename( $path ) { return basename( $path ); }
}
if ( ! function_exists( 'sanitize_file_name' ) ) {
	function sanitize_file_name( $name ) { return preg_replace( '/[^A-Za-z0-9._-]/', '', $name ); }
}
