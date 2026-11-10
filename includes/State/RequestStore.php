<?php
namespace WpSpidCie\State;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages pending authentication requests state (anti-replay & correlation).
 */
class RequestStore {

	/**
	 * Save pending request state.
	 *
	 * @param string $request_id
	 * @param array  $data
	 * @return void
	 */
	public static function set( $request_id, $data ) {
		set_transient( 'wpspid_req_' . $request_id, $data, 10 * MINUTE_IN_SECONDS );
	}

	/**
	 * Get and consume (delete) pending request state.
	 *
	 * @param string $request_id
	 * @return array|false
	 */
	public static function consume( $request_id ) {
		$key = 'wpspid_req_' . $request_id;
		$data = get_transient( $key );
		if ( false !== $data ) {
			delete_transient( $key );
			return $data;
		}
		return false;
	}
}
