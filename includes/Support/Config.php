<?php
namespace WpSpidCie\Support;

use WpSpidCie\Settings\OptionsManager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Central read access to plugin configuration (option `wpspid_options`, merged with defaults).
 */
class Config {

	public static function options() {
		$stored = get_option( OptionsManager::OPTION, array() );
		return array_merge( OptionsManager::defaults(), is_array( $stored ) ? $stored : array() );
	}

	public static function get( $key, $default = '' ) {
		$o = self::options();
		return array_key_exists( $key, $o ) ? $o[ $key ] : $default;
	}

	public static function is_enabled() {
		return (bool) self::get( 'enabled', false );
	}

	public static function is_production() {
		return (bool) self::get( 'production', false );
	}

	public static function is_public() {
		return 'private' !== self::get( 'sp_type', 'public' );
	}

	/** entityID: configured value, or the metadata URL as a last resort. */
	public static function entity_id( $service = 'spid' ) {
		$eid = trim( (string) self::get( 'entity_id', '' ) );
		return '' !== $eid ? $eid : home_url( '/?wpspid=metadata&service=' . $service );
	}

	public static function acs_url() {
		return home_url( '/?wpspid=acs' );
	}

	public static function slo_url() {
		return home_url( '/?wpspid=slo' );
	}

	public static function acs_index() {
		return (int) self::get( 'acs_index', 0 );
	}

	/** 'entity_id' (behaviour of spid-php) or 'sso_url'. To be confirmed with the AgID validator. */
	public static function destination_mode() {
		return 'sso_url' === self::get( 'destination_mode', 'entity_id' ) ? 'sso_url' : 'entity_id';
	}

	/** Default CIE level (as in wp-auth-gov-proxy): 2. */
	public static function cie_level() {
		return max( 1, min( 3, (int) self::get( 'cie_level', 2 ) ) );
	}

	/**
	 * Value of the X.509 organizationIdentifier (Avviso SPID n.29 v.3):
	 * PA:IT-<IPA> | VATIT-<P.IVA> | CF:IT-<CF>.
	 */
	public static function organization_identifier() {
		$code = (string) self::get( 'org_code', '' );
		if ( self::is_public() ) {
			return 'PA:IT-' . $code;
		}
		return ( 'FiscalCode' === self::get( 'org_code_type', 'VATNumber' ) ? 'CF:IT-' : 'VATIT-' ) . $code;
	}

	/** Attributes requested in the metadata and required in the Response. */
	public static function required_attributes( $service = 'spid' ) {
		if ( 'cie' === $service ) {
			return array( 'fiscalNumber', 'name', 'familyName', 'dateOfBirth' );
		}
		$attrs = self::get( 'attributes', array() );
		return ( is_array( $attrs ) && $attrs ) ? array_values( $attrs ) : OptionsManager::default_attributes();
	}
}
