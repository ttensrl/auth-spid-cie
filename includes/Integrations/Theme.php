<?php
namespace WpSpidCie\Integrations;

use WpSpidCie\Support\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Integrazione con il tema WP Digital Italia (e i suoi child: ASL, Comuni, Scuole):
 *  - `dci_area_personale`: il pulsante "Area personale" dell'header porta al login SPID/CIE e,
 *    da collegato, mostra il nome del cittadino;
 *  - `wpspid_logo_url`: fornisce il logo CIE del tema (il plugin non lo include).
 * Senza il tema i due filtri non vengono mai chiamati: sono innocui.
 */
class Theme {

	public static function register() {
		add_filter( 'dci_area_personale', array( __CLASS__, 'area_personale' ), 20 );
		add_filter( 'wpspid_logo_url', array( __CLASS__, 'logo' ), 10, 2 );
	}

	/**
	 * @param array $area {label, url}
	 * @return array
	 */
	public static function area_personale( $area ) {
		if ( ! Config::is_enabled() ) {
			return $area;
		}
		$area        = (array) $area;
		$area['url'] = home_url( '/?wpspid=choose' );
		if ( function_exists( 'wpspid_is_authenticated' ) && wpspid_is_authenticated() ) {
			$area['label'] = self::label( wpspid_get_attributes(), isset( $area['label'] ) ? $area['label'] : '' );
		}
		return $area;
	}

	/** Nome del cittadino, o l'etichetta di partenza se gli attributi non lo contengono. */
	public static function label( array $attrs, $fallback ) {
		$name = trim( ( isset( $attrs['name'] ) ? $attrs['name'] : '' ) . ' ' . ( isset( $attrs['familyName'] ) ? $attrs['familyName'] : '' ) );
		return '' !== $name ? $name : $fallback;
	}

	/** Logo CIE del tema, solo se il plugin non ne ha gia' uno. */
	public static function logo( $url, $service ) {
		if ( 'cie' !== $service || '' !== $url ) {
			return $url;
		}
		$rel = '/assets/images/identity/cie-bianco.svg';
		return file_exists( get_template_directory() . $rel ) ? get_template_directory_uri() . $rel : $url;
	}
}
