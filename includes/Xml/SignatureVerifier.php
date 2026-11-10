<?php
namespace WpSpidCie\Xml;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * XML Digital Signature verification (enveloped, RSA, exclusive C14N).
 *
 * The only public entry point is verify_element(): it proves that a *specific*
 * element (the one the caller is going to read data from) is covered by a valid
 * signature made with one of the trusted certificates. Callers must then read
 * data only from that element.
 */
class SignatureVerifier {

	const NS_DS  = 'http://www.w3.org/2000/09/xmldsig#';
	const NS_EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#';

	const ALG_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

	private static $sig_algos = array(
		'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => OPENSSL_ALGO_SHA256,
		'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => OPENSSL_ALGO_SHA384,
		'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => OPENSSL_ALGO_SHA512,
	);

	private static $digest_algos = array(
		'http://www.w3.org/2001/04/xmlenc#sha256'        => 'sha256',
		'http://www.w3.org/2001/04/xmldsig-more#sha384'  => 'sha384',
		'http://www.w3.org/2001/04/xmlenc#sha384'        => 'sha384',
		'http://www.w3.org/2001/04/xmlenc#sha512'        => 'sha512',
	);

	/**
	 * Does the element have a direct ds:Signature child?
	 */
	public static function has_signature( \DOMElement $element ) {
		return count( self::collect( $element, self::NS_DS, 'Signature' ) ) > 0;
	}

	/**
	 * Verify that $element carries a valid enveloped signature made by one of $certs.
	 *
	 * @param \DOMDocument $doc    Document containing the element.
	 * @param \DOMElement  $element Element that must be signed (Response, Assertion, EntityDescriptor...).
	 * @param string[]     $certs  Trusted certificates (PEM or bare base64 DER).
	 * @return void
	 * @throws \Exception On any failure.
	 */
	public static function verify_element( \DOMDocument $doc, \DOMElement $element, array $certs ) {
		if ( empty( $certs ) ) {
			throw new \Exception( 'No trusted certificate available.' );
		}

		$id = $element->getAttribute( 'ID' );
		if ( '' === $id ) {
			throw new \Exception( 'Signed element has no ID attribute.' );
		}

		// The ID must be unique in the whole document (anti signature-wrapping).
		$count = 0;
		foreach ( $doc->getElementsByTagName( '*' ) as $node ) {
			if ( $node->getAttribute( 'ID' ) === $id ) {
				$count++;
			}
		}
		if ( 1 !== $count ) {
			throw new \Exception( 'Element ID is not unique in the document.' );
		}

		// Exactly one direct ds:Signature child.
		$signatures = self::collect( $element, self::NS_DS, 'Signature' );
		if ( 1 !== count( $signatures ) ) {
			throw new \Exception( 'Element must have exactly one ds:Signature.' );
		}
		$signature = $signatures[0];

		$signed_infos = self::collect( $signature, self::NS_DS, 'SignedInfo' );
		if ( 1 !== count( $signed_infos ) ) {
			throw new \Exception( 'Signature must have exactly one SignedInfo.' );
		}
		$signed_info = $signed_infos[0];

		// CanonicalizationMethod: exclusive C14N without comments only.
		$c14n_methods = self::collect( $signed_info, self::NS_DS, 'CanonicalizationMethod' );
		if ( 1 !== count( $c14n_methods ) || self::NS_EXC !== $c14n_methods[0]->getAttribute( 'Algorithm' ) ) {
			throw new \Exception( 'Unsupported canonicalization algorithm.' );
		}
		$si_prefixes = self::inclusive_prefixes( $c14n_methods[0] );

		// SignatureMethod: RSA-SHA2 only.
		$sig_methods = self::collect( $signed_info, self::NS_DS, 'SignatureMethod' );
		if ( 1 !== count( $sig_methods ) ) {
			throw new \Exception( 'Missing SignatureMethod.' );
		}
		$sig_alg = $sig_methods[0]->getAttribute( 'Algorithm' );
		if ( ! isset( self::$sig_algos[ $sig_alg ] ) ) {
			throw new \Exception( 'Unsupported or insecure signature algorithm: ' . $sig_alg );
		}
		$openssl_algo = self::$sig_algos[ $sig_alg ];

		// Exactly one Reference, pointing at this very element.
		$references = self::collect( $signed_info, self::NS_DS, 'Reference' );
		if ( 1 !== count( $references ) ) {
			throw new \Exception( 'SignedInfo must contain exactly one Reference.' );
		}
		$reference = $references[0];
		if ( $reference->getAttribute( 'URI' ) !== '#' . $id ) {
			throw new \Exception( 'Reference URI does not point to the signed element.' );
		}

		// Transforms: enveloped-signature (required) + exclusive C14N (optional).
		$ref_prefixes  = array();
		$has_enveloped = false;
		foreach ( self::collect( $reference, self::NS_DS, 'Transforms' ) as $transforms ) {
			foreach ( self::collect( $transforms, self::NS_DS, 'Transform' ) as $transform ) {
				$alg = $transform->getAttribute( 'Algorithm' );
				if ( self::ALG_ENVELOPED === $alg ) {
					$has_enveloped = true;
				} elseif ( self::NS_EXC === $alg ) {
					$ref_prefixes = self::inclusive_prefixes( $transform );
				} else {
					throw new \Exception( 'Unsupported transform: ' . $alg );
				}
			}
		}
		if ( ! $has_enveloped ) {
			throw new \Exception( 'Enveloped-signature transform is required.' );
		}

		// Digest.
		$digest_methods = self::collect( $reference, self::NS_DS, 'DigestMethod' );
		$digest_alg     = 1 === count( $digest_methods ) ? $digest_methods[0]->getAttribute( 'Algorithm' ) : '';
		if ( ! isset( self::$digest_algos[ $digest_alg ] ) ) {
			throw new \Exception( 'Unsupported or insecure digest algorithm: ' . $digest_alg );
		}
		$digest_values = self::collect( $reference, self::NS_DS, 'DigestValue' );
		if ( 1 !== count( $digest_values ) ) {
			throw new \Exception( 'Missing DigestValue.' );
		}
		$expected_digest = preg_replace( '/\s+/', '', $digest_values[0]->textContent );

		// Enveloped transform: take the Signature out of the real tree (so that the
		// namespace context of ancestors is preserved), canonicalize, put it back.
		$parent  = $signature->parentNode;
		$next    = $signature->nextSibling;
		$parent->removeChild( $signature );
		try {
			$canonical = $element->C14N( true, false, null, $ref_prefixes ? $ref_prefixes : null );
		} finally {
			$parent->insertBefore( $signature, $next );
		}
		$calculated = base64_encode( hash( self::$digest_algos[ $digest_alg ], $canonical, true ) );
		if ( ! hash_equals( $expected_digest, $calculated ) ) {
			throw new \Exception( 'XML signature digest verification failed.' );
		}

		// SignatureValue over canonical SignedInfo.
		$sig_values = self::collect( $signature, self::NS_DS, 'SignatureValue' );
		if ( 1 !== count( $sig_values ) ) {
			throw new \Exception( 'Missing SignatureValue.' );
		}
		$signature_value = base64_decode( preg_replace( '/\s+/', '', $sig_values[0]->textContent ), true );
		if ( false === $signature_value || '' === $signature_value ) {
			throw new \Exception( 'Invalid SignatureValue encoding.' );
		}
		$canonical_si = $signed_info->C14N( true, false, null, $si_prefixes ? $si_prefixes : null );

		// Trusted certificates only: KeyInfo inside the message is never used.
		foreach ( $certs as $cert ) {
			$key = openssl_pkey_get_public( self::to_pem( $cert ) );
			if ( false === $key ) {
				continue;
			}
			if ( 1 === openssl_verify( $canonical_si, $signature_value, $key, $openssl_algo ) ) {
				return;
			}
		}

		throw new \Exception( 'XML signature cryptographic verification failed.' );
	}

	/**
	 * Normalise a certificate (bare base64 or PEM) to PEM.
	 */
	public static function to_pem( $cert ) {
		$cert = trim( (string) $cert );
		if ( false !== strpos( $cert, 'BEGIN CERTIFICATE' ) ) {
			return $cert;
		}
		$body = preg_replace( '/\s+/', '', $cert );
		return "-----BEGIN CERTIFICATE-----\n" . chunk_split( $body, 64, "\n" ) . "-----END CERTIFICATE-----\n";
	}

	/**
	 * Direct element children with given namespace/localName.
	 *
	 * @return \DOMElement[]
	 */
	private static function collect( \DOMElement $parent, $ns, $local ) {
		$out = array();
		foreach ( $parent->childNodes as $child ) {
			if ( $child instanceof \DOMElement && $child->namespaceURI === $ns && $child->localName === $local ) {
				$out[] = $child;
			}
		}
		return $out;
	}

	/**
	 * Prefix list of an exc-c14n InclusiveNamespaces child, if any.
	 *
	 * @return string[]
	 */
	private static function inclusive_prefixes( \DOMElement $method ) {
		foreach ( $method->childNodes as $child ) {
			if ( $child instanceof \DOMElement && $child->namespaceURI === self::NS_EXC && 'InclusiveNamespaces' === $child->localName ) {
				$list = preg_split( '/\s+/', trim( $child->getAttribute( 'PrefixList' ) ), -1, PREG_SPLIT_NO_EMPTY );
				return $list ? $list : array();
			}
		}
		return array();
	}
}
