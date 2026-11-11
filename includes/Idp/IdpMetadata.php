<?php
namespace AuthSpidCie\Idp;

use AuthSpidCie\Xml\XmlSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Parses an IdP SAML metadata document into the plugin's IdP array.
 */
class IdpMetadata {

	/**
	 * @param string $xml Metadata XML (EntityDescriptor).
	 * @return array|null {entity_id, sso[], slo[], certs[]} or null if unusable.
	 */
	public static function parse( $xml ) {
		try {
			$doc = XmlSecurity::load_xml( $xml );
		} catch ( \Exception $e ) {
			return null;
		}
		$xp     = XmlSecurity::get_xpath( $doc );
		$entity = $xp->query( '/md:EntityDescriptor' )->item( 0 );
		if ( ! $entity || '' === $entity->getAttribute( 'entityID' ) ) {
			return null;
		}

		$idp = array(
			'entity_id' => $entity->getAttribute( 'entityID' ),
			'sso'       => array(),
			'slo'       => array(),
			'certs'     => array(),
		);

		$base = '/md:EntityDescriptor/md:IDPSSODescriptor';
		foreach ( $xp->query( $base . '/md:KeyDescriptor[not(@use) or @use="signing"]//ds:X509Certificate' ) as $c ) {
			$idp['certs'][] = preg_replace( '/\s+/', '', $c->textContent );
		}
		foreach ( $xp->query( $base . '/md:SingleSignOnService' ) as $e ) {
			$idp['sso'][] = array( 'binding' => $e->getAttribute( 'Binding' ), 'location' => $e->getAttribute( 'Location' ) );
		}
		foreach ( $xp->query( $base . '/md:SingleLogoutService' ) as $e ) {
			$idp['slo'][] = array( 'binding' => $e->getAttribute( 'Binding' ), 'location' => $e->getAttribute( 'Location' ) );
		}
		$idp['certs'] = array_values( array_unique( $idp['certs'] ) );

		return ( $idp['sso'] && $idp['certs'] ) ? $idp : null;
	}

	/**
	 * Fetch and parse an IdP metadata URL.
	 *
	 * @param string $url          https URL.
	 * @param bool   $insecure_tls Skip TLS verification (local test environments only).
	 * @return array|null
	 */
	public static function fetch( $url, $insecure_tls = false ) {
		if ( 0 !== strpos( $url, 'https://' ) ) {
			return null;
		}
		$response = wp_remote_get( $url, array( 'timeout' => 15, 'sslverify' => ! $insecure_tls ) );
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}
		return self::parse( wp_remote_retrieve_body( $response ) );
	}
}
