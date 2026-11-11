<?php
namespace WpSpidCie\Cert;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Dove stanno chiavi, certificati e metadata registrato: nel database, mai in file.
 *
 * Si usano le opzioni "di rete" (`*_site_option`): in un multisite stanno in `sitemeta`, quindi un solo
 * certificato per tutta la rete come prima; in un sito singolo WordPress le scrive in `options` con
 * autoload = 'no', cosi' la chiave non viene caricata a ogni richiesta.
 */
class Storage {

	const PREFIX = 'wpspid_';

	private static function name( $name ) {
		return self::PREFIX . preg_replace( '/[^a-z0-9_]/', '', strtolower( (string) $name ) );
	}

	/** @return array|null */
	public static function get( $name ) {
		$v = get_site_option( self::name( $name ), null );
		return is_array( $v ) ? $v : null;
	}

	public static function set( $name, array $value ) {
		update_site_option( self::name( $name ), $value );
	}

	public static function delete( $name ) {
		delete_site_option( self::name( $name ) );
	}
}
