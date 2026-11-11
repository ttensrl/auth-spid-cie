<?php
namespace AuthSpidCie\Ui;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * [spid_button], [cie_button], [authspidcie_login]. Attributi: return (URL di ritorno), level (1-3).
 */
class Shortcodes {

	public static function register() {
		add_shortcode( 'spid_button', array( __CLASS__, 'spid' ) );
		add_shortcode( 'cie_button', array( __CLASS__, 'cie' ) );
		add_shortcode( 'authspidcie_login', array( __CLASS__, 'login' ) );
	}

	private static function args( $atts, $tag ) {
		$atts = shortcode_atts( array( 'return' => '', 'level' => '' ), (array) $atts, $tag );
		$out  = array( 'return' => $atts['return'] ? wp_validate_redirect( esc_url_raw( $atts['return'] ), '' ) : '' );
		if ( '' !== $atts['level'] ) {
			$out['level'] = max( 1, min( 3, (int) $atts['level'] ) );
		}
		return $out;
	}

	public static function spid( $atts = array() ) {
		return Buttons::spid_button( self::args( $atts, 'spid_button' ) );
	}

	public static function cie( $atts = array() ) {
		return Buttons::cie_button( self::args( $atts, 'cie_button' ) );
	}

	public static function login( $atts = array() ) {
		return Buttons::page( array( 'return' => self::args( $atts, 'authspidcie_login' )['return'] ) );
	}
}
