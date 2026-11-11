<?php
namespace WpSpidCie\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** Log diagnostico: scrive solo se WP_DEBUG_LOG e' attivo (o via filtro). */
class Log {
	public static function write( $message ) {
		$on = defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG;
		if ( apply_filters( 'wpspid_log_enabled', $on ) ) {
			error_log( $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- log opzionale, attivo solo con WP_DEBUG_LOG
		}
	}
}
