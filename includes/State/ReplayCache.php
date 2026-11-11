<?php
namespace AuthSpidCie\State;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Remembers Response/Assertion IDs already accepted, to refuse replays.
 */
class ReplayCache {

	/**
	 * Mark an ID as seen.
	 *
	 * @param string $id        Message ID.
	 * @param int    $valid_until UNIX time until which the message could still be valid.
	 * @return bool True if first time seen, false if it is a replay.
	 */
	public static function mark( $id, $valid_until ) {
		$key = 'authspidcie_seen_' . md5( $id );
		if ( false !== get_transient( $key ) ) {
			return false;
		}
		$ttl = max( 300, (int) $valid_until - time() + 600 );
		set_transient( $key, 1, $ttl );
		return true;
	}
}
