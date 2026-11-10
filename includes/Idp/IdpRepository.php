<?php
namespace WpSpidCie\Idp;

use WpSpidCie\Support\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Repository for Identity Providers.
 */
class IdpRepository {

	/**
	 * Get all enabled IdPs (SPID and CIE).
	 *
	 * @return array Array of IdP objects.
	 */
	public static function get_all() {
		$all = array();
		if ( Config::get( 'spid_enabled', true ) ) {
			$all = array_merge( $all, self::get_spid_idps(), TestIdps::get_all() );
		}
		if ( Config::get( 'cie_enabled', true ) ) {
			$all = array_merge( $all, self::get_cie_idps() );
		}
		return $all;
	}

	/**
	 * Get SPID IdPs.
	 *
	 * @return array
	 */
	public static function get_spid_idps() {
		return Registry::get_instance()->get_idps();
	}

	/**
	 * Get CIE IdPs (endpoints and certificates from the official CIE metadata).
	 *
	 * @return array
	 */
	public static function get_cie_idps() {
		return array( CieMetadata::get_idp( Config::is_production() ) );
	}

	/**
	 * Find an IdP by entity ID.
	 *
	 * @param string $entity_id
	 * @return array|false
	 */
	public static function find_by_entity_id( $entity_id ) {
		$idps = self::get_all();
		foreach ( $idps as $idp ) {
			if ( $idp['entity_id'] === $entity_id ) {
				return $idp;
			}
		}
		return false;
	}
}
