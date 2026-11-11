<?php
// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- i messaggi delle eccezioni non vengono stampati direttamente: chi li mostra li esegue con esc_html().
namespace WpSpidCie\Xml;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles XML Digital Signature (XMLDSig) creation.
 */
class Signer {

	/**
	 * Sign an XML element using enveloped signature.
	 *
	 * @param \DOMElement $root The element to sign (e.g. AuthnRequest, EntityDescriptor).
	 * @param string      $private_key PEM private key.
	 * @param string      $certificate PEM certificate (public).
	 * @return void
	 * @throws \Exception
	 */
	public static function sign( \DOMElement $root, $private_key, $certificate ) {
		$id = $root->getAttribute( 'ID' );
		if ( ! $id ) {
			throw new \Exception( 'Cannot sign element without an ID.' );
		}

		$doc = $root->ownerDocument;

		// 1. Create Signature element.
		$signature = $doc->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:Signature' );
		
		// Insert after Issuer if it exists (for AuthnRequest/Response), otherwise at the beginning (for EntityDescriptor).
		$issuer = $root->getElementsByTagNameNS( 'urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer' )->item( 0 );
		if ( ! $issuer ) {
			$issuer = $root->getElementsByTagNameNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'Issuer' )->item( 0 );
		}

		if ( $issuer && $issuer->parentNode === $root ) {
			$root->insertBefore( $signature, $issuer->nextSibling );
		} else {
			$root->insertBefore( $signature, $root->firstChild );
		}

		// 2. Build SignedInfo.
		$signed_info = $doc->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:SignedInfo' );
		$signature->appendChild( $signed_info );

		$canonicalization_method = $doc->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:CanonicalizationMethod' );
		$canonicalization_method->setAttribute( 'Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#' );
		$signed_info->appendChild( $canonicalization_method );

		$signature_method = $doc->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:SignatureMethod' );
		$signature_method->setAttribute( 'Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' );
		$signed_info->appendChild( $signature_method );

		// 3. Build Reference.
		$reference = $doc->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:Reference' );
		$reference->setAttribute( 'URI', '#' . $id );
		$signed_info->appendChild( $reference );

		$transforms = $doc->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:Transforms' );
		$reference->appendChild( $transforms );

		$transform_enveloped = $doc->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:Transform' );
		$transform_enveloped->setAttribute( 'Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature' );
		$transforms->appendChild( $transform_enveloped );

		$transform_c14n = $doc->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:Transform' );
		$transform_c14n->setAttribute( 'Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#' );
		$transforms->appendChild( $transform_c14n );

		$digest_method = $doc->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:DigestMethod' );
		$digest_method->setAttribute( 'Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256' );
		$reference->appendChild( $digest_method );

		// 4. Calculate Digest.
		// Remove signature before calculating digest of the root element.
		$signature_parent = $signature->parentNode;
		$signature_parent->removeChild( $signature );
		
		$canonicalized_data = $root->C14N( true, false );
		$digest_value_str = base64_encode( hash( 'sha256', $canonicalized_data, true ) );
		
		// Re-insert signature.
		if ( $issuer && $issuer->parentNode === $root ) {
			$root->insertBefore( $signature, $issuer->nextSibling );
		} else {
			$root->insertBefore( $signature, $root->firstChild );
		}

		$digest_value = \WpSpidCie\Xml\XmlSecurity::text_element( $doc, 'http://www.w3.org/2000/09/xmldsig#', 'ds:DigestValue', $digest_value_str );
		$reference->appendChild( $digest_value );

		// 5. Calculate SignatureValue.
		$canonicalized_signed_info = $signed_info->C14N( true, false );
		$signature_res = null;
		if ( ! openssl_sign( $canonicalized_signed_info, $signature_res, $private_key, OPENSSL_ALGO_SHA256 ) ) {
			throw new \Exception( 'Failed to sign: ' . openssl_error_string() );
		}

		$signature_value = \WpSpidCie\Xml\XmlSecurity::text_element( $doc, 'http://www.w3.org/2000/09/xmldsig#', 'ds:SignatureValue', base64_encode( $signature_res ) );
		$signature->appendChild( $signature_value );

		// 6. Add KeyInfo with certificate.
		$key_info = $doc->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:KeyInfo' );
		$signature->appendChild( $key_info );

		$x509_data = $doc->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:X509Data' );
		$key_info->appendChild( $x509_data );

		// Clean certificate from PEM headers and whitespace.
		$cert_clean = preg_replace( '/\-+BEGIN CERTIFICATE\-+|\-+END CERTIFICATE\-+|\s+/', '', $certificate );
		$x509_certificate = \WpSpidCie\Xml\XmlSecurity::text_element( $doc, 'http://www.w3.org/2000/09/xmldsig#', 'ds:X509Certificate', $cert_clean );
		$x509_data->appendChild( $x509_certificate );
	}
}
