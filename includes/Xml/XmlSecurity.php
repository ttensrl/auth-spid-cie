<?php
namespace WpSpidCie\Xml;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Utility for safe XML loading and manipulation.
 */
class XmlSecurity {

	/**
	 * Load an XML string securely (no DOCTYPE, no entities, no network).
	 *
	 * @param string $xml XML string.
	 * @return \DOMDocument
	 * @throws \Exception If XML is invalid or unsafe.
	 */
	public static function load_xml( $xml ) {
		if ( ! is_string( $xml ) || '' === $xml ) {
			throw new \Exception( 'XML string is empty.' );
		}

		// Reject any DTD up front (XXE / entity expansion).
		if ( preg_match( '/<!DOCTYPE|<!ENTITY/i', $xml ) ) {
			throw new \Exception( 'DOCTYPE is not allowed in XML.' );
		}

		$previous = libxml_use_internal_errors( true );
		libxml_clear_errors();

		$doc = new \DOMDocument();
		// No LIBXML_NOENT / LIBXML_DTDLOAD: entities are never substituted or loaded.
		$ok     = $doc->loadXML( $xml, LIBXML_NONET | LIBXML_NOWARNING | LIBXML_NOERROR );
		$errors = libxml_get_errors();
		libxml_clear_errors();
		libxml_use_internal_errors( $previous );

		if ( ! $ok ) {
			$msg = ! empty( $errors ) ? trim( $errors[0]->message ) : 'Unknown XML error.';
			throw new \Exception( 'Invalid XML: ' . $msg );
		}

		// Second line of defence (e.g. documents in other encodings).
		if ( null !== $doc->doctype ) {
			throw new \Exception( 'DOCTYPE is not allowed in XML.' );
		}

		return $doc;
	}

	/**
	 * Create a namespaced element with a text value. Unlike passing the value to
	 * createElementNS(), the text is escaped (a raw "&" would otherwise truncate it).
	 *
	 * @return \DOMElement
	 */
	public static function text_element( \DOMDocument $doc, $ns, $qname, $text ) {
		$el = $doc->createElementNS( $ns, $qname );
		$el->appendChild( $doc->createTextNode( (string) $text ) );
		return $el;
	}

	/**
	 * Parse an xs:dateTime (must carry an explicit timezone) to a UNIX timestamp.
	 *
	 * @param string $value
	 * @return int
	 * @throws \Exception
	 */
	public static function parse_time( $value ) {
		$value = trim( (string) $value );
		if ( '' === $value || ! preg_match( '/(Z|[+-]\d{2}:\d{2})$/', $value ) ) {
			throw new \Exception( 'Invalid or timezone-less dateTime: ' . $value );
		}
		try {
			return ( new \DateTimeImmutable( $value ) )->getTimestamp();
		} catch ( \Exception $e ) {
			throw new \Exception( 'Invalid dateTime: ' . $value );
		}
	}

	/**
	 * Helper for XPath with pre-registered namespaces.
	 *
	 * @param \DOMDocument $doc
	 * @return \DOMXPath
	 */
	public static function get_xpath( \DOMDocument $doc ) {
		$xpath = new \DOMXPath( $doc );
		$xpath->registerNamespace( 'saml', 'urn:oasis:names:tc:SAML:2.0:assertion' );
		$xpath->registerNamespace( 'samlp', 'urn:oasis:names:tc:SAML:2.0:protocol' );
		$xpath->registerNamespace( 'md', 'urn:oasis:names:tc:SAML:2.0:metadata' );
		$xpath->registerNamespace( 'ds', 'http://www.w3.org/2000/09/xmldsig#' );
		$xpath->registerNamespace( 'spid', 'https://spid.gov.it/saml-extensions' );
		$xpath->registerNamespace( 'cie', 'https://www.cartaidentita.interno.gov.it/saml-extensions' );
		return $xpath;
	}
}
