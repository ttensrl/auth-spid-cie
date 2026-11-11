<?php
namespace WpSpidCie\Auth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * "Gate" mode: SPID/CIE session for citizens without a WordPress account.
 *
 * Uses the PHP session (so that the legacy theme code reading
 * $_SESSION['govauth_user_data'] keeps working) with hardened handling:
 * session id regenerated on login, cookie flags, absolute lifetime, and no
 * session started for anonymous visitors on read.
 */
class SessionGate {

	const KEY_LEGACY = 'govauth_user_data';
	const KEY_META   = 'wpspid_session';

	/**
	 * Make the session available.
	 *
	 * @param bool $create Start a brand new session if none exists (login only).
	 */
	public static function start( $create = false ) {
		if ( PHP_SESSION_ACTIVE === session_status() ) {
			return true;
		}
		if ( headers_sent() ) {
			return false;
		}
		if ( ! $create && ! isset( $_COOKIE[ session_name() ] ) ) {
			return false; // Anonymous visitor: do not open a session (page caching friendly).
		}
		session_set_cookie_params( array(
			'lifetime' => 0,
			'path'     => '/',
			'secure'   => function_exists( 'is_ssl' ) ? is_ssl() : false,
			'httponly' => true,
			'samesite' => 'Lax',
		) );
		return session_start();
	}

	public static function login( array $attributes, array $meta = array() ) {
		if ( ! self::start( true ) ) {
			throw new \Exception( 'Unable to start the session.' );
		}
		session_regenerate_id( true );
		$_SESSION[ self::KEY_LEGACY ] = $attributes;
		$_SESSION[ self::KEY_META ]   = array_merge( $meta, array( 'time' => time() ) );
	}

	public static function logout() {
		if ( ! self::start() ) {
			return;
		}
		unset( $_SESSION[ self::KEY_LEGACY ], $_SESSION[ self::KEY_META ] );
		session_regenerate_id( true );
	}

	public static function is_authenticated() {
		return self::meta() !== array() && ! empty( $_SESSION[ self::KEY_LEGACY ] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- dati scritti dal plugin stesso
	}

	public static function attributes() {
		return self::is_authenticated() ? (array) $_SESSION[ self::KEY_LEGACY ] : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- dati scritti dal plugin stesso
	}

	/** Session metadata (idp, name_id, session_index, level, time) or empty array. */
	public static function meta() {
		if ( ! self::start() || empty( $_SESSION[ self::KEY_META ] ) ) {
			return array();
		}
		$meta     = (array) $_SESSION[ self::KEY_META ]; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- dati scritti dal plugin stesso
		$lifetime = (int) apply_filters( 'wpspid_session_lifetime', 2 * HOUR_IN_SECONDS );
		if ( empty( $meta['time'] ) || time() - (int) $meta['time'] > $lifetime ) {
			unset( $_SESSION[ self::KEY_LEGACY ], $_SESSION[ self::KEY_META ] );
			return array();
		}
		return $meta;
	}
}
