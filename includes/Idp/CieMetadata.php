<?php
namespace WpSpidCie\Idp;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * CIE Identity Provider: endpoints and signing certificates from the official
 * Shibboleth metadata (fetched over TLS and cached).
 *
 * If the metadata cannot be fetched/parsed the IdP is returned WITHOUT certificates:
 * the login route refuses to start (fail closed) instead of trusting nothing-verifiable.
 */
class CieMetadata {

	const URL_PROD = 'https://idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata';
	const URL_TEST = 'https://preproduzione.idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata';

	const ENTITY_PROD = 'https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO';
	const ENTITY_TEST = 'https://preproduzione.idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO';

	public static function get_idp( $production ) {
		$key    = 'wpspid_cie_' . ( $production ? 'prod' : 'test' );
		$cached = get_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$idp = self::fetch( $production );
		set_transient( $key, $idp, empty( $idp['certs'] ) ? 5 * MINUTE_IN_SECONDS : 12 * HOUR_IN_SECONDS );
		return $idp;
	}

	public static function refresh() {
		delete_transient( 'wpspid_cie_prod' );
		delete_transient( 'wpspid_cie_test' );
	}

	private static function fetch( $production ) {
		$idp = array(
			'entity_id'    => $production ? self::ENTITY_PROD : self::ENTITY_TEST,
			'name'         => $production ? 'CIE' : 'CIE (test)',
			'display_name' => $production ? 'Carta d\'Identità Elettronica' : 'Carta d\'Identità Elettronica (test)',
			'logo'         => '',
			'type'         => 'cie',
			'sso'          => array(),
			'slo'          => array(),
			'certs'        => array(),
		);

		$response = wp_remote_get( $production ? self::URL_PROD : self::URL_TEST, array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return $idp;
		}

		$parsed = IdpMetadata::parse( wp_remote_retrieve_body( $response ) );
		if ( $parsed ) {
			$idp = array_merge( $idp, $parsed );
		}

		return $idp;
	}
}
