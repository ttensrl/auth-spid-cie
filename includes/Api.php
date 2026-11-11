<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Public API functions for themes and other plugins.
 */

if ( ! function_exists( 'authspidcie_is_authenticated' ) ) {
	function authspidcie_is_authenticated() {
		return \AuthSpidCie\Auth\SessionGate::is_authenticated();
	}
}

if ( ! function_exists( 'authspidcie_get_attributes' ) ) {
	function authspidcie_get_attributes() {
		return \AuthSpidCie\Auth\SessionGate::attributes();
	}
}

if ( ! function_exists( 'authspidcie_get_attribute' ) ) {
	function authspidcie_get_attribute( $name ) {
		$attrs = authspidcie_get_attributes();
		return isset( $attrs[ $name ] ) ? $attrs[ $name ] : '';
	}
}

if ( ! function_exists( 'authspidcie_login_url' ) ) {
	function authspidcie_login_url( $idp_entity_id, $level = 2, $return_to = '' ) {
		$args = array(
			'authspidcie' => 'login',
			'idp'    => $idp_entity_id,
			'level'  => max( 1, min( 3, (int) $level ) ),
		);
		if ( ! empty( $return_to ) ) {
			$args['returnTo'] = $return_to;
		}
		return add_query_arg( array_map( 'rawurlencode', $args ), home_url( '/' ) );
	}
}

if ( ! function_exists( 'authspidcie_logout_url' ) ) {
	function authspidcie_logout_url( $return_to = '' ) {
		$args = array(
			'authspidcie'   => 'slo',
			'_wpnonce' => wp_create_nonce( 'authspidcie_logout' ),
		);
		if ( ! empty( $return_to ) ) {
			$args['returnTo'] = rawurlencode( $return_to );
		}
		return add_query_arg( $args, home_url( '/' ) );
	}
}
