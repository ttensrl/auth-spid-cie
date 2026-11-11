<?php
namespace AuthSpidCie\Idp;

use AuthSpidCie\Support\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Identity providers used for testing (SPID Demo, Demo in Validator mode, AgID Validator,
 * and custom metadata URLs such as the local spid-saml-check / spid-sp-test IdPs).
 *
 * NEVER returned when the production flag is on: a production SP must not accept them.
 */
class TestIdps {

	const DEMO           = 'https://demo.spid.gov.it/metadata.xml';
	const DEMO_VALIDATOR = 'https://demo.spid.gov.it/validator/metadata.xml';
	const VALIDATOR      = 'https://validator.spid.gov.it/metadata.xml';

	public static function get_all() {
		if ( Config::is_production() ) {
			return array();
		}

		$sources = array();
		if ( Config::get( 'test_demo', true ) ) {
			$sources[] = array( self::DEMO, 'SPID Demo' );
		}
		if ( Config::get( 'test_demo_validator', false ) ) {
			$sources[] = array( self::DEMO_VALIDATOR, 'SPID Demo (Validator mode)' );
		}
		if ( Config::get( 'test_validator', false ) ) {
			$sources[] = array( self::VALIDATOR, 'SPID Validator' );
		}
		foreach ( (array) Config::get( 'test_idp_urls', array() ) as $url ) {
			$host      = wp_parse_url( $url, PHP_URL_HOST );
			$sources[] = array( $url, 'Test IdP: ' . ( $host ? $host : $url ) );
		}

		$insecure = (bool) Config::get( 'test_insecure_tls', false );
		$out      = array();

		$pasted = trim( (string) Config::get( 'test_idp_xml', '' ) );
		if ( '' !== $pasted ) {
			$idp = IdpMetadata::parse( $pasted );
			if ( $idp ) {
				$out[] = array_merge( $idp, array(
					'name'         => 'Test IdP (pasted metadata)',
					'display_name' => 'Test IdP (pasted metadata)',
					'logo'         => '',
					'type'         => 'spid',
					'test'         => true,
				) );
			}
		}

		foreach ( $sources as $src ) {
			$idp = self::load( $src[0], $insecure );
			if ( $idp ) {
				$out[] = array_merge( $idp, array(
					'name'         => $src[1],
					'display_name' => $src[1],
					'logo'         => '',
					'type'         => 'spid',
					'test'         => true,
				) );
			}
		}
		return $out;
	}

	private static function load( $url, $insecure ) {
		$key    = 'authspidcie_test_' . md5( $url );
		$cached = get_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached ? $cached : null; // empty array = cached failure.
		}
		$idp = IdpMetadata::fetch( $url, $insecure );
		set_transient( $key, $idp ? $idp : array(), $idp ? HOUR_IN_SECONDS : 5 * MINUTE_IN_SECONDS );
		return $idp;
	}

	public static function refresh() {
		global $wpdb;
		if ( isset( $wpdb ) ) {
			$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_authspidcie\_test\_%' OR option_name LIKE '\_transient\_timeout\_authspidcie\_test\_%'" ); // phpcs:ignore WordPress.DB
		}
	}
}
