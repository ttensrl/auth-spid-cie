<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Public API functions for themes and other plugins.
 */

if ( ! function_exists( 'wpspid_is_authenticated' ) ) {
	function wpspid_is_authenticated() {
		return \WpSpidCie\Auth\SessionGate::is_authenticated();
	}
}

if ( ! function_exists( 'wpspid_get_attributes' ) ) {
	function wpspid_get_attributes() {
		return \WpSpidCie\Auth\SessionGate::attributes();
	}
}

if ( ! function_exists( 'wpspid_get_attribute' ) ) {
	function wpspid_get_attribute( $name ) {
		$attrs = wpspid_get_attributes();
		return isset( $attrs[ $name ] ) ? $attrs[ $name ] : '';
	}
}

if ( ! function_exists( 'wpspid_login_url' ) ) {
	function wpspid_login_url( $idp_entity_id, $level = 2, $return_to = '' ) {
		$args = array(
			'wpspid' => 'login',
			'idp'    => $idp_entity_id,
			'level'  => max( 1, min( 3, (int) $level ) ),
		);
		if ( ! empty( $return_to ) ) {
			$args['returnTo'] = $return_to;
		}
		return add_query_arg( array_map( 'rawurlencode', $args ), home_url( '/' ) );
	}
}

if ( ! function_exists( 'wpspid_logout_url' ) ) {
	function wpspid_logout_url( $return_to = '' ) {
		$args = array(
			'wpspid'   => 'slo',
			'_wpnonce' => wp_create_nonce( 'wpspid_logout' ),
		);
		if ( ! empty( $return_to ) ) {
			$args['returnTo'] = rawurlencode( $return_to );
		}
		return add_query_arg( $args, home_url( '/' ) );
	}
}
