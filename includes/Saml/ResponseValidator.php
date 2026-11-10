<?php
namespace WpSpidCie\Saml;

use WpSpidCie\Xml\SignatureVerifier;
use WpSpidCie\Xml\XmlSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Validates the SAML Response received on the ACS.
 *
 * Rules derived from the "SPID CUSTOM" patches of spid-cie-php (see
 * ANALISI_E_ISTRUZIONI.md §4.3). Data is read ONLY from the Assertion whose
 * signature has been verified against the IdP certificates.
 */
class ResponseValidator {

	const NS_SAML  = 'urn:oasis:names:tc:SAML:2.0:assertion';
	const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
	const SUCCESS  = 'urn:oasis:names:tc:SAML:2.0:status:Success';
	const ENTITY   = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity';
	const TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
	const BEARER   = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
	const MAX_SIZE = 524288;

	/**
	 * Read the (still unverified) InResponseTo of a Response, to locate the pending request.
	 *
	 * @return string Empty string if not found/invalid.
	 */
	public static function peek_in_response_to( $saml_response_base64 ) {
		try {
			$doc = XmlSecurity::load_xml( self::decode( $saml_response_base64 ) );
			$el  = $doc->documentElement;
			if ( $el && self::NS_SAMLP === $el->namespaceURI && 'Response' === $el->localName ) {
				return trim( $el->getAttribute( 'InResponseTo' ) );
			}
		} catch ( \Exception $e ) {
			// fall through.
		}
		return '';
	}

	/**
	 * Validate a Response.
	 *
	 * @param string $saml_response_base64 Raw POST value.
	 * @param array  $exp Expectations:
	 *   request_id (string), idp_entity_id (string), certs (string[]), sp_entity_id (string),
	 *   acs_url (string), level (int), comparison (string), service ('spid'|'cie'),
	 *   required_attributes (string[]), now (int, optional), skew (int, default 180),
	 *   max_age (int, default 60).
	 * @return array {attributes, name_id, session_index, response_id, assertion_id,
	 *                not_on_or_after, authn_class_ref}
	 * @throws ValidationException
	 */
	public static function validate( $saml_response_base64, array $exp ) {
		$exp = array_merge(
			array(
				'comparison'          => 'minimum',
				'service'             => 'spid',
				'required_attributes' => array(),
				'skew'                => 180,
				'max_age'             => 60,
			),
			$exp
		);
		$now     = isset( $exp['now'] ) ? (int) $exp['now'] : time();
		$skew    = (int) $exp['skew'];
		$max_age = (int) $exp['max_age'];
		$is_cie  = 'cie' === $exp['service'];

		try {
			return self::do_validate( $saml_response_base64, $exp, $now, $skew, $max_age, $is_cie );
		} catch ( ValidationException $e ) {
			throw $e;
		} catch ( \Exception $e ) {
			throw new ValidationException( $e->getMessage(), 'invalid', array() );
		}
	}

	private static function do_validate( $b64, array $exp, $now, $skew, $max_age, $is_cie ) {
		$doc  = XmlSecurity::load_xml( self::decode( $b64 ) );
		$xp   = XmlSecurity::get_xpath( $doc );
		$resp = $doc->documentElement;

		if ( ! $resp || self::NS_SAMLP !== $resp->namespaceURI || 'Response' !== $resp->localName ) {
			throw new ValidationException( 'Il documento non è una SAML Response.', 'structure' );
		}

		// --- Status first: error responses carry no assertion. ---
		$status = $xp->query( './samlp:Status/samlp:StatusCode', $resp )->item( 0 );
		if ( ! $status ) {
			throw new ValidationException( 'StatusCode mancante.', 'structure' );
		}
		if ( self::SUCCESS !== $status->getAttribute( 'Value' ) ) {
			$msg = $xp->query( './samlp:Status/samlp:StatusMessage', $resp )->item( 0 );
			throw new ValidationException(
				'Autenticazione non riuscita presso il gestore di identità.',
				'idp_error',
				array(
					'status'  => $status->getAttribute( 'Value' ),
					'message' => $msg ? trim( $msg->textContent ) : '',
				)
			);
		}

		// --- Exactly ONE assertion in the whole document, never encrypted. ---
		if ( $xp->query( '//saml:EncryptedAssertion' )->length > 0 ) {
			throw new ValidationException( 'Assertion cifrate non supportate.', 'structure' );
		}
		if ( 1 !== $xp->query( '//saml:Assertion' )->length ) {
			throw new ValidationException( 'La Response deve contenere esattamente una Assertion.', 'structure' );
		}
		$assertions = $xp->query( './saml:Assertion', $resp );
		if ( 1 !== $assertions->length ) {
			throw new ValidationException( 'Assertion non figlia diretta della Response.', 'structure' );
		}
		$a = $assertions->item( 0 );

		// --- Signatures: Assertion is mandatory; Response too if it carries one. ---
		try {
			SignatureVerifier::verify_element( $doc, $a, $exp['certs'] );
			if ( SignatureVerifier::has_signature( $resp ) ) {
				SignatureVerifier::verify_element( $doc, $resp, $exp['certs'] );
			}
		} catch ( \Exception $e ) {
			throw new ValidationException( 'Verifica della firma digitale fallita.', 'signature', array( 'error' => $e->getMessage() ) );
		}

		// --- Response-level checks. ---
		self::require_eq( $resp->getAttribute( 'Version' ), '2.0', 'Versione SAML non valida.' );
		self::require_nonempty( $resp->getAttribute( 'ID' ), 'ID della Response mancante.' );
		self::require_eq( $resp->getAttribute( 'InResponseTo' ), $exp['request_id'], 'InResponseTo non corrisponde alla richiesta.', 'in_response_to' );
		self::require_eq( $resp->getAttribute( 'Destination' ), $exp['acs_url'], 'Destination non corrisponde all\'ACS.', 'destination' );
		self::check_instant( $resp->getAttribute( 'IssueInstant' ), $now, $max_age, $skew, 'Response' );

		$r_issuer = $xp->query( './saml:Issuer', $resp )->item( 0 );
		if ( $r_issuer ) {
			self::require_eq( trim( $r_issuer->textContent ), $exp['idp_entity_id'], 'Issuer della Response non valido.', 'issuer' );
			if ( ! $is_cie ) {
				self::require_eq( $r_issuer->getAttribute( 'Format' ), self::ENTITY, 'Format dell\'Issuer della Response non valido.', 'issuer' );
			}
		} elseif ( ! $is_cie ) {
			throw new ValidationException( 'Issuer della Response mancante.', 'issuer' );
		}

		// --- Assertion-level checks (all signed data). ---
		self::require_eq( $a->getAttribute( 'Version' ), '2.0', 'Versione Assertion non valida.' );
		self::require_nonempty( $a->getAttribute( 'ID' ), 'ID dell\'Assertion mancante.' );
		self::check_instant( $a->getAttribute( 'IssueInstant' ), $now, $max_age, $skew, 'Assertion' );

		$a_issuer = $xp->query( './saml:Issuer', $a )->item( 0 );
		if ( ! $a_issuer ) {
			throw new ValidationException( 'Issuer dell\'Assertion mancante.', 'issuer' );
		}
		self::require_eq( trim( $a_issuer->textContent ), $exp['idp_entity_id'], 'Issuer dell\'Assertion non valido.', 'issuer' );
		if ( ! $is_cie ) {
			self::require_eq( $a_issuer->getAttribute( 'Format' ), self::ENTITY, 'Format dell\'Issuer dell\'Assertion non valido.', 'issuer' );
		}

		// NameID.
		$name_id = $xp->query( './saml:Subject/saml:NameID', $a )->item( 0 );
		if ( ! $name_id || '' === trim( $name_id->textContent ) ) {
			throw new ValidationException( 'NameID mancante.', 'subject' );
		}
		if ( ! $is_cie ) {
			self::require_eq( $name_id->getAttribute( 'Format' ), self::TRANSIENT, 'Format del NameID non valido.', 'subject' );
			self::require_nonempty( $name_id->getAttribute( 'NameQualifier' ), 'NameQualifier del NameID mancante.', 'subject' );
		}

		// SubjectConfirmation (bearer).
		$confirmed = false;
		$noa_max   = 0;
		foreach ( $xp->query( './saml:Subject/saml:SubjectConfirmation', $a ) as $sc ) {
			if ( self::BEARER !== $sc->getAttribute( 'Method' ) ) {
				continue;
			}
			$scd = $xp->query( './saml:SubjectConfirmationData', $sc )->item( 0 );
			if ( ! $scd ) {
				continue;
			}
			self::require_eq( $scd->getAttribute( 'Recipient' ), $exp['acs_url'], 'Recipient non corrisponde all\'ACS.', 'recipient' );
			self::require_eq( $scd->getAttribute( 'InResponseTo' ), $exp['request_id'], 'InResponseTo della SubjectConfirmationData non valido.', 'in_response_to' );
			$noa = self::time( $scd->getAttribute( 'NotOnOrAfter' ), 'NotOnOrAfter mancante o non valido.' );
			if ( $noa + $skew <= $now ) {
				throw new ValidationException( 'SubjectConfirmationData scaduta.', 'expired' );
			}
			$noa_max   = $noa;
			$confirmed = true;
			break;
		}
		if ( ! $confirmed ) {
			throw new ValidationException( 'SubjectConfirmation bearer mancante.', 'subject' );
		}

		// Conditions + Audience.
		$cond = $xp->query( './saml:Conditions', $a )->item( 0 );
		if ( ! $cond ) {
			throw new ValidationException( 'Conditions mancanti.', 'conditions' );
		}
		$nb  = $cond->getAttribute( 'NotBefore' );
		$noa = $cond->getAttribute( 'NotOnOrAfter' );
		if ( ! $is_cie && ( '' === trim( $nb ) || '' === trim( $noa ) ) ) {
			throw new ValidationException( 'NotBefore/NotOnOrAfter mancanti nelle Conditions.', 'conditions' );
		}
		if ( '' !== trim( $nb ) && self::time( $nb, 'NotBefore non valido.' ) > $now + $skew ) {
			throw new ValidationException( 'Assertion non ancora valida.', 'expired' );
		}
		if ( '' !== trim( $noa ) ) {
			$noa_ts = self::time( $noa, 'NotOnOrAfter non valido.' );
			if ( $noa_ts + $skew <= $now ) {
				throw new ValidationException( 'Assertion scaduta.', 'expired' );
			}
			$noa_max = max( $noa_max, $noa_ts );
		}
		$audience_ok = false;
		foreach ( $xp->query( './saml:AudienceRestriction/saml:Audience', $cond ) as $aud ) {
			if ( trim( $aud->textContent ) === $exp['sp_entity_id'] ) {
				$audience_ok = true;
			}
		}
		if ( ! $audience_ok ) {
			throw new ValidationException( 'Audience non corrisponde al Service Provider.', 'audience' );
		}

		// AuthnStatement / level.
		$authn = $xp->query( './saml:AuthnStatement', $a )->item( 0 );
		if ( ! $authn ) {
			throw new ValidationException( 'AuthnStatement mancante.', 'authn' );
		}
		$ref_node = $xp->query( './saml:AuthnContext/saml:AuthnContextClassRef', $authn )->item( 0 );
		$class_ref = $ref_node ? trim( $ref_node->textContent ) : '';
		if ( '' === $class_ref ) {
			throw new ValidationException( 'AuthnContextClassRef mancante.', 'authn' );
		}
		if ( preg_match( '#^https://www\.spid\.gov\.it/SpidL([123])$#', $class_ref, $m ) ) {
			self::check_level( (int) $m[1], (int) $exp['level'], $exp['comparison'] );
		} elseif ( ! $is_cie ) {
			throw new ValidationException( 'AuthnContextClassRef non valido.', 'authn', array( 'value' => $class_ref ) );
		}
		// CIE: unknown class refs are accepted (spid-php "CIE bypass"); see docs/TODO-validator.md.

		// Attributes (from the signed assertion only).
		$attributes = array();
		foreach ( $xp->query( './saml:AttributeStatement/saml:Attribute', $a ) as $attr ) {
			$name = $attr->getAttribute( 'Name' );
			if ( '' === $name ) {
				continue;
			}
			$val_node = $xp->query( './saml:AttributeValue', $attr )->item( 0 );
			$attributes[ $name ] = $val_node ? trim( $val_node->textContent ) : '';
		}
		if ( ! $is_cie && empty( $attributes ) ) {
			throw new ValidationException( 'AttributeStatement mancante o vuoto.', 'attributes' );
		}
		$missing = array();
		foreach ( $exp['required_attributes'] as $req ) {
			if ( ! array_key_exists( $req, $attributes ) ) {
				$missing[] = $req;
			}
		}
		if ( $missing ) {
			throw new ValidationException( 'Attributi richiesti non ricevuti.', 'attributes', array( 'missing' => $missing ) );
		}
		if ( isset( $attributes['fiscalNumber'] ) && 0 === strpos( $attributes['fiscalNumber'], 'TINIT-' ) ) {
			$attributes['fiscalNumber'] = substr( $attributes['fiscalNumber'], 6 );
		}

		return array(
			'attributes'      => $attributes,
			'name_id'         => trim( $name_id->textContent ),
			'session_index'   => $authn->getAttribute( 'SessionIndex' ),
			'response_id'     => $resp->getAttribute( 'ID' ),
			'assertion_id'    => $a->getAttribute( 'ID' ),
			'not_on_or_after' => $noa_max,
			'authn_class_ref' => $class_ref,
		);
	}

	private static function check_level( $received, $requested, $comparison ) {
		switch ( $comparison ) {
			case 'exact':
				$ok = ( $received === $requested );
				break;
			case 'maximum':
				$ok = ( $received <= $requested );
				break;
			case 'minimum':
			default:
				$ok = ( $received >= $requested );
		}
		if ( ! $ok ) {
			throw new ValidationException(
				'Livello di autenticazione non accettabile.',
				'level',
				array( 'requested' => $requested, 'received' => $received, 'comparison' => $comparison )
			);
		}
	}

	private static function check_instant( $value, $now, $max_age, $skew, $what ) {
		$ts = self::time( $value, 'IssueInstant ' . $what . ' non valido.' );
		if ( $ts < $now - $max_age ) {
			throw new ValidationException( $what . ' scaduta (IssueInstant troppo vecchio). Verificare l\'orologio del server.', 'expired' );
		}
		if ( $ts > $now + $skew ) {
			throw new ValidationException( $what . ' emessa nel futuro. Verificare l\'orologio del server.', 'expired' );
		}
	}

	private static function time( $value, $message ) {
		try {
			return XmlSecurity::parse_time( $value );
		} catch ( \Exception $e ) {
			throw new ValidationException( $message, 'conditions' );
		}
	}

	private static function require_eq( $actual, $expected, $message, $reason = 'invalid' ) {
		if ( ! is_string( $actual ) || '' === $actual || ! hash_equals( (string) $expected, $actual ) ) {
			throw new ValidationException( $message, $reason );
		}
	}

	private static function require_nonempty( $value, $message, $reason = 'invalid' ) {
		if ( '' === trim( (string) $value ) ) {
			throw new ValidationException( $message, $reason );
		}
	}

	private static function decode( $b64 ) {
		$b64 = preg_replace( '/\s+/', '', (string) $b64 );
		if ( '' === $b64 || strlen( $b64 ) > self::MAX_SIZE * 2 ) {
			throw new ValidationException( 'SAMLResponse vuota o troppo grande.', 'structure' );
		}
		$xml = base64_decode( $b64, true );
		if ( false === $xml || '' === $xml || strlen( $xml ) > self::MAX_SIZE ) {
			throw new ValidationException( 'SAMLResponse non valida.', 'structure' );
		}
		return $xml;
	}
}
