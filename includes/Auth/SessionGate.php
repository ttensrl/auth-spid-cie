<?php
namespace WpSpidCie\Auth;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * "Gate" mode: SPID/CIE session for citizens without a WordPress account.
 *
 * It does NOT use PHP sessions. At login a random 256-bit identifier is put in an
 * HttpOnly cookie; the SAML attributes stay on the server (transient, so they follow the
 * site's object cache) under the SHA-256 of that identifier. Consequences:
 * - no session_start(): no lock between parallel requests, no Site Health warning;
 * - works with several web servers as long as WordPress storage is shared;
 * - logout and expiry are enforced server-side;
 * - anonymous visitors never get a cookie, so page caching is untouched.
 */
class SessionGate {

	const COOKIE = 'wpspid_sid';
	const PREFIX = 'wpspid_sess_';

	/** @var array|null|false Per-request cache: array = loaded session, false = none, null = not read yet. */
	private static $loaded = null;

	private static function lifetime() {
		return max( 60, (int) apply_filters( 'wpspid_session_lifetime', 2 * HOUR_IN_SECONDS ) );
	}

	private static function sid_from_cookie() {
		$sid = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		return preg_match( '/^[a-f0-9]{64}$/', $sid ) ? $sid : '';
	}

	private static function key( $sid ) {
		return self::PREFIX . hash( 'sha256', $sid );
	}

	private static function set_cookie( $value, $expires ) {
		$path = defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/';
		return setcookie( self::COOKIE, $value, array(
			'expires'  => $expires,
			'path'     => $path,
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		) );
	}

	/**
	 * Open a session for an authenticated citizen. The identifier is always brand new.
	 *
	 * @param array $attributes SAML attributes.
	 * @param array $meta       idp, name_id, session_index, ...
	 * @throws \Exception When the cookie can no longer be sent.
	 */
	public static function login( array $attributes, array $meta = array() ) {
		if ( headers_sent() ) {
			throw new \Exception( 'Unable to start the session: headers already sent.' );
		}
		$old = self::sid_from_cookie();
		if ( '' !== $old ) {
			delete_transient( self::key( $old ) );
		}
		$sid  = bin2hex( random_bytes( 32 ) );
		$data = array(
			'attributes' => $attributes,
			'meta'       => array_merge( $meta, array( 'time' => time() ) ),
		);
		set_transient( self::key( $sid ), $data, self::lifetime() );
		self::set_cookie( $sid, 0 );
		$_COOKIE[ self::COOKIE ] = $sid;
		self::$loaded            = $data;
	}

	public static function logout() {
		$sid = self::sid_from_cookie();
		if ( '' !== $sid ) {
			delete_transient( self::key( $sid ) );
			if ( ! headers_sent() ) {
				self::set_cookie( '', time() - YEAR_IN_SECONDS );
			}
		}
		unset( $_COOKIE[ self::COOKIE ] );
		self::$loaded = false;
	}

	private static function load() {
		if ( null !== self::$loaded ) {
			return self::$loaded;
		}
		self::$loaded = false;
		$sid          = self::sid_from_cookie();
		if ( '' === $sid ) {
			return false; // Anonymous visitor.
		}
		$data = get_transient( self::key( $sid ) );
		if ( ! is_array( $data ) || empty( $data['meta']['time'] ) || empty( $data['attributes'] ) ) {
			return false;
		}
		if ( time() - (int) $data['meta']['time'] > self::lifetime() ) {
			delete_transient( self::key( $sid ) );
			return false;
		}
		self::$loaded = $data;
		return $data;
	}

	public static function is_authenticated() {
		return false !== self::load();
	}

	public static function attributes() {
		$d = self::load();
		return $d ? (array) $d['attributes'] : array();
	}

	/** Session metadata (idp, name_id, session_index, level, time) or empty array. */
	public static function meta() {
		$d = self::load();
		return $d ? (array) $d['meta'] : array();
	}

	/** For tests: forget the per-request cache. */
	public static function reset_cache() {
		self::$loaded = null;
	}
}
