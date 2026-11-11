<?php
namespace WpSpidCie\Saml;

use WpSpidCie\Cert\CertificateManager;
use WpSpidCie\Support\Config;
use WpSpidCie\Xml\Signer;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds the SAML AuthnRequest (always signed).
 */
class AuthnRequestBuilder {

	const COMPARISON = 'minimum';

	/**
	 * @param string $idp_entity_id   Target IdP entityID.
	 * @param string $sso_url         SSO endpoint used for transport.
	 * @param int    $level           1..3 (clamped).
	 * @param string $service         'spid' or 'cie'.
	 * @param bool   $embed_signature true for HTTP-POST (XMLDSig); false for HTTP-Redirect
	 *                                (signature then travels in the query string).
	 * @return array {xml, id, level, comparison}
	 * @throws \Exception If SP key/certificate are missing: unsigned requests are never sent.
	 */
	public static function build( $idp_entity_id, $sso_url, $level = 2, $service = 'spid', $embed_signature = true ) {
		$level = max( 1, min( 3, (int) $level ) );

		$cert = CertificateManager::get_certificate( $service );
		if ( ! $cert ) {
			throw new \Exception( 'Service Provider certificate or private key missing: unable to sign the request.' );
		}
		$private_key = CertificateManager::private_key_or_fail( $service ); // Spiega perche' la chiave non e' leggibile.

		$entity_id     = Config::entity_id( $service );
		$id            = 'wpspid_' . bin2hex( random_bytes( 16 ) );
		$issue_instant = gmdate( 'Y-m-d\TH:i:s\Z' );
		// spid-php puts the IdP entityID in Destination; configurable, to be confirmed with the validator.
		$destination   = 'sso_url' === Config::destination_mode() ? $sso_url : $idp_entity_id;

		$doc               = new \DOMDocument( '1.0', 'UTF-8' );
		$doc->formatOutput = false;

		$request = $doc->createElementNS( 'urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:AuthnRequest' );
		$request->setAttributeNS( 'http://www.w3.org/2000/xmlns/', 'xmlns:saml', 'urn:oasis:names:tc:SAML:2.0:assertion' );
		$request->setAttribute( 'ID', $id );
		$request->setAttribute( 'Version', '2.0' );
		$request->setAttribute( 'IssueInstant', $issue_instant );
		$request->setAttribute( 'Destination', $destination );
		$request->setAttribute( 'ProtocolBinding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' );
		$request->setAttribute( 'AssertionConsumerServiceURL', Config::acs_url() );
		$request->setAttribute( 'ForceAuthn', 'true' );
		$request->setAttribute( 'AttributeConsumingServiceIndex', (string) Config::acs_index() );
		$doc->appendChild( $request );

		$issuer = \WpSpidCie\Xml\XmlSecurity::text_element( $doc, 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Issuer', $entity_id );
		$issuer->setAttribute( 'Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity' );
		$issuer->setAttribute( 'NameQualifier', $entity_id );
		$request->appendChild( $issuer );

		$policy = $doc->createElementNS( 'urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:NameIDPolicy' );
		$policy->setAttribute( 'Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' );
		$request->appendChild( $policy );

		$ctx = $doc->createElementNS( 'urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:RequestedAuthnContext' );
		$ctx->setAttribute( 'Comparison', self::COMPARISON );
		$request->appendChild( $ctx );

		// SPID and CIE both use the SpidL{n} class refs (as spid-php does).
		$ref = \WpSpidCie\Xml\XmlSecurity::text_element( $doc, 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnContextClassRef', 'https://www.spid.gov.it/SpidL' . $level );
		$ctx->appendChild( $ref );

		// Work on a re-parsed copy so that signing canonicalizes the same tree a verifier will parse.
		$doc     = \WpSpidCie\Xml\XmlSecurity::load_xml( $doc->saveXML() );
		$request = $doc->documentElement;
		if ( $embed_signature ) {
			Signer::sign( $request, $private_key, $cert );
		}

		return array(
			'xml'        => $doc->saveXML( $doc->documentElement ),
			'id'         => $id,
			'level'      => $level,
			'comparison' => self::COMPARISON,
		);
	}
}
