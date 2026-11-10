<?php
namespace WpSpidCie\Idp;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages the SPID IdP registry (JSON).
 */
class Registry {
	private static $instance = null;
	const TRANSIENT_KEY = 'wpspid_registry_spid';
	const REGISTRY_URL = 'https://registry.spid.gov.it/entities-idp?output=json';

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Get list of SPID IdPs.
	 *
	 * @return array
	 */
	public function get_idps() {
		$cached = get_transient( self::TRANSIENT_KEY );
		if ( false !== $cached ) {
			return $cached;
		}

		$idps = $this->fetch_and_parse();
		if ( empty( $idps ) ) {
			// Fallback to the bundled snapshot of the registry.
			$fixture = WPSPID_PLUGIN_DIR . 'resources/spid-idps.json';
			if ( file_exists( $fixture ) ) {
				$json = file_get_contents( $fixture );
				$data = json_decode( $json, true );
				if ( ! empty( $data ) ) {
					$idps = $this->parse_raw_registry( $data );
				}
			}
		}

		if ( ! empty( $idps ) ) {
			set_transient( self::TRANSIENT_KEY, $idps, 12 * HOUR_IN_SECONDS );
		}

		return $idps;
	}

	public function refresh() {
		delete_transient( self::TRANSIENT_KEY );
		return $this->get_idps();
	}

	private function fetch_and_parse() {
		$response = wp_remote_get( self::REGISTRY_URL, array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) ) {
			return array();
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( empty( $data ) ) {
			return array();
		}

		return $this->parse_raw_registry( $data );
	}

	private function parse_raw_registry( $data ) {
		$idps = array();
		// The format can be an array of IdPs or wrapped in an object.
		$items = isset( $data['entities'] ) ? $data['entities'] : $data;
		if ( ! is_array( $items ) ) {
			return array();
		}

		foreach ( $items as $item ) {
			// Ignore deleted or disabled
			if ( self::is_flag_set( isset( $item['_deleted'] ) ? $item['_deleted'] : '' ) || self::is_flag_set( isset( $item['_disabled'] ) ? $item['_disabled'] : '' ) ) {
				continue;
			}

			$entity_id = isset( $item['entity_id'] ) ? $item['entity_id'] : ( isset( $item['entityID'] ) ? $item['entityID'] : '' );
			if ( ! $entity_id ) {
				continue;
			}

			$name = isset( $item['organization_name'] ) ? $item['organization_name'] : ( isset( $item['name'] ) ? $item['name'] : $entity_id );
			$display_name = isset( $item['organization_display_name'] ) ? $item['organization_display_name'] : $name;
			$logo = isset( $item['logo_uri'] ) ? $item['logo_uri'] : '';

			$sso = self::normalize_endpoints( isset( $item['single_sign_on_service'] ) ? $item['single_sign_on_service'] : array() );
			$slo = self::normalize_endpoints( isset( $item['single_logout_service'] ) ? $item['single_logout_service'] : array() );
			$certs = isset( $item['signing_certificate_x509'] ) ? $item['signing_certificate_x509'] : array();

			$idps[] = array(
				'entity_id'    => $entity_id,
				'name'         => $name,
				'display_name' => $display_name,
				'logo'         => $logo,
				'type'         => 'spid',
				'sso'          => $sso,
				'slo'          => $slo,
				'certs'        => $certs,
			);
		}

		return $idps;
	}

	/**
	 * The registry uses 'Binding'/'Location'; the rest of the plugin uses lowercase keys.
	 */
	private static function normalize_endpoints( $endpoints ) {
		$out = array();
		if ( ! is_array( $endpoints ) ) {
			return $out;
		}
		foreach ( $endpoints as $ep ) {
			$binding  = isset( $ep['Binding'] ) ? $ep['Binding'] : ( isset( $ep['binding'] ) ? $ep['binding'] : '' );
			$location = isset( $ep['Location'] ) ? $ep['Location'] : ( isset( $ep['location'] ) ? $ep['location'] : '' );
			if ( $binding && $location ) {
				$out[] = array( 'binding' => $binding, 'location' => $location );
			}
		}
		return $out;
	}

	/**
	 * The registry encodes flags as 'Y'/'N' strings ('N' is NOT empty()).
	 */
	private static function is_flag_set( $value ) {
		return in_array( strtolower( (string) $value ), array( 'y', 'yes', 'true', '1' ), true );
	}
}
