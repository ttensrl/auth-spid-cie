<?php
namespace AuthSpidCie\Saml;

use AuthSpidCie\Cert\CertificateManager;
use AuthSpidCie\Support\Config;
use AuthSpidCie\Xml\Signer;
use AuthSpidCie\Xml\XmlSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds and signs the Service Provider metadata for SPID and CIE
 * (Avviso SPID n.29 v.3, CIE extensions; structure as produced by spid-php).
 */
class MetadataBuilder {

	const NS_MD   = 'urn:oasis:names:tc:SAML:2.0:metadata';
	const NS_DS   = 'http://www.w3.org/2000/09/xmldsig#';
	const NS_SPID = 'https://spid.gov.it/saml-extensions';
	const NS_FPA  = 'https://spid.gov.it/invoicing-extensions';
	const NS_CIE  = 'https://www.cartaidentita.interno.gov.it/saml-extensions';
	const XMLNS   = 'http://www.w3.org/2000/xmlns/';

	/**
	 * @param string $service 'spid' or 'cie'.
	 * @return string Signed metadata XML.
	 * @throws \Exception If the SP key/certificate is missing.
	 */
	public static function generate( $service = 'spid' ) {
		$service = 'cie' === $service ? 'cie' : 'spid';
		$c       = Config::options();
		$is_cie  = 'cie' === $service;
		$public  = Config::is_public();

		$entity_id = Config::entity_id( $service );
		$cert      = CertificateManager::get_certificate( $service );
		if ( ! $cert ) {
			throw new \Exception( 'Certificate or private key missing: unable to sign the metadata.' );
		}
		$key = CertificateManager::private_key_or_fail( $service ); // Spiega perche' la chiave non e' leggibile.

		$org_name    = self::first( $c['org_name'], get_bloginfo( 'name' ) );
		$org_display = self::first( $c['org_display_name'], $org_name );
		$org_url     = self::first( $c['org_url'], home_url( '/' ) );
		$sp_name     = self::first( $c['sp_name'], $org_display );
		$sp_desc     = self::first( $c['sp_description'], $sp_name );
		$email       = self::first( $c['contact_email'], get_option( 'admin_email' ) );
		$phone       = (string) $c['contact_phone'];

		$doc = new \DOMDocument( '1.0', 'UTF-8' );

		$root = $doc->createElementNS( self::NS_MD, 'md:EntityDescriptor' );
		$root->setAttribute( 'entityID', $entity_id );
		$root->setAttribute( 'ID', '_' . bin2hex( random_bytes( 16 ) ) );
		if ( $is_cie ) {
			$root->setAttributeNS( self::XMLNS, 'xmlns:cie', self::NS_CIE );
		} else {
			$root->setAttributeNS( self::XMLNS, 'xmlns:spid', self::NS_SPID );
			if ( ! $public ) {
				$root->setAttributeNS( self::XMLNS, 'xmlns:fpa', self::NS_FPA );
			}
		}
		$doc->appendChild( $root );

		// --- SPSSODescriptor ---
		$sp = $doc->createElementNS( self::NS_MD, 'md:SPSSODescriptor' );
		$sp->setAttribute( 'protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol' );
		$sp->setAttribute( 'AuthnRequestsSigned', 'true' );
		$sp->setAttribute( 'WantAssertionsSigned', 'true' );
		$root->appendChild( $sp );

		$cert_clean = preg_replace( '/\-+BEGIN CERTIFICATE\-+|\-+END CERTIFICATE\-+|\s+/', '', $cert );
		foreach ( array( 'signing', 'encryption' ) as $use ) {
			$kd = $doc->createElementNS( self::NS_MD, 'md:KeyDescriptor' );
			$kd->setAttribute( 'use', $use );
			$ki = $doc->createElementNS( self::NS_DS, 'ds:KeyInfo' );
			$xd = $doc->createElementNS( self::NS_DS, 'ds:X509Data' );
			$xd->appendChild( XmlSecurity::text_element( $doc, self::NS_DS, 'ds:X509Certificate', $cert_clean ) );
			$ki->appendChild( $xd );
			$kd->appendChild( $ki );
			$sp->appendChild( $kd );
		}

		foreach ( array( 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' ) as $binding ) {
			$slo = $doc->createElementNS( self::NS_MD, 'md:SingleLogoutService' );
			$slo->setAttribute( 'Binding', $binding );
			$slo->setAttribute( 'Location', Config::slo_url() );
			$sp->appendChild( $slo );
		}

		$sp->appendChild( XmlSecurity::text_element( $doc, self::NS_MD, 'md:NameIDFormat', 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' ) );

		$acs = $doc->createElementNS( self::NS_MD, 'md:AssertionConsumerService' );
		$acs->setAttribute( 'index', '0' );
		$acs->setAttribute( 'isDefault', 'true' );
		$acs->setAttribute( 'Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' );
		$acs->setAttribute( 'Location', Config::acs_url() );
		$sp->appendChild( $acs );

		$acs_svc = $doc->createElementNS( self::NS_MD, 'md:AttributeConsumingService' );
		$acs_svc->setAttribute( 'index', (string) Config::acs_index() );
		$name = XmlSecurity::text_element( $doc, self::NS_MD, 'md:ServiceName', $sp_name );
		$name->setAttribute( 'xml:lang', 'it' );
		$acs_svc->appendChild( $name );
		$desc = XmlSecurity::text_element( $doc, self::NS_MD, 'md:ServiceDescription', $sp_desc );
		$desc->setAttribute( 'xml:lang', 'it' );
		$acs_svc->appendChild( $desc );
		foreach ( Config::required_attributes( $service ) as $attr ) {
			$ra = $doc->createElementNS( self::NS_MD, 'md:RequestedAttribute' );
			$ra->setAttribute( 'Name', $attr );
			$ra->setAttribute( 'NameFormat', 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic' );
			$acs_svc->appendChild( $ra );
		}
		$sp->appendChild( $acs_svc );

		// --- Organization ---
		$org = $doc->createElementNS( self::NS_MD, 'md:Organization' );
		foreach ( array( 'OrganizationName' => $org_name, 'OrganizationDisplayName' => $org_display, 'OrganizationURL' => $org_url ) as $tag => $value ) {
			$el = XmlSecurity::text_element( $doc, self::NS_MD, 'md:' . $tag, $value );
			$el->setAttribute( 'xml:lang', 'it' );
			$org->appendChild( $el );
		}
		$root->appendChild( $org );

		// --- ContactPerson ---
		if ( $is_cie ) {
			$ext = array();
			if ( $public ) {
				$ext[] = array( self::NS_CIE, 'cie:Public', '' );
				$ext[] = array( self::NS_CIE, 'cie:IPACode', $c['org_code'] );
			} else {
				$ext[] = array( self::NS_CIE, 'cie:Private', '' );
				$ext[] = array( self::NS_CIE, 'cie:VATNumber', 'VATNumber' === $c['org_code_type'] ? $c['org_code'] : '' );
				$ext[] = array( self::NS_CIE, 'cie:FiscalCode', self::first( $c['cie_fiscal_code'], 'FiscalCode' === $c['org_code_type'] ? $c['org_code'] : '' ) );
				$ext[] = array( self::NS_CIE, 'cie:NACE2Code', $c['cie_nace2'] );
			}
			$ext[] = array( self::NS_CIE, 'cie:Municipality', $c['cie_municipality'] );
			$ext[] = array( self::NS_CIE, 'cie:Province', $c['cie_province'] );
			$ext[] = array( self::NS_CIE, 'cie:Country', $c['country'] );
			$root->appendChild( self::contact( $doc, 'administrative', $ext, $org_name, $email, $phone ) );
		} else {
			$ext = array();
			if ( $public ) {
				$ext[] = array( self::NS_SPID, 'spid:IPACode', $c['org_code'] );
				$ext[] = array( self::NS_SPID, 'spid:Public', '' );
			} else {
				$is_fc = 'FiscalCode' === $c['org_code_type'];
				$code  = (string) $c['org_code'];
				// spid:VATNumber MUST start with the ISO 3166 country code (validator rule).
				if ( ! $is_fc && ! preg_match( '/^[A-Za-z]{2}/', $code ) ) {
					$code = strtoupper( (string) $c['country'] ) . $code;
				}
				$ext[] = array( self::NS_SPID, $is_fc ? 'spid:FiscalCode' : 'spid:VATNumber', $code );
				$ext[] = array( self::NS_SPID, 'spid:Private', '' );
			}
			$root->appendChild( self::contact( $doc, 'other', $ext, $org_name, $email, $phone ) );

			if ( ! $public ) {
				$root->appendChild( self::billing_contact( $doc, $c ) );
			}
		}

		// Sign a re-parsed copy: canonicalization is then computed on exactly the tree
		// any consumer will obtain when parsing the published XML.
		$doc  = XmlSecurity::load_xml( $doc->saveXML() );
		$root = $doc->documentElement;
		Signer::sign( $root, $key, $cert );

		return $doc->saveXML();
	}

	/** ContactPerson with namespaced extension children. */
	private static function contact( \DOMDocument $doc, $type, array $extensions, $company, $email, $phone ) {
		$cp = $doc->createElementNS( self::NS_MD, 'md:ContactPerson' );
		$cp->setAttribute( 'contactType', $type );

		$ext_el = $doc->createElementNS( self::NS_MD, 'md:Extensions' );
		foreach ( $extensions as $e ) {
			$ext_el->appendChild( XmlSecurity::text_element( $doc, $e[0], $e[1], $e[2] ) );
		}
		$cp->appendChild( $ext_el );

		$cp->appendChild( XmlSecurity::text_element( $doc, self::NS_MD, 'md:Company', $company ) );
		$cp->appendChild( XmlSecurity::text_element( $doc, self::NS_MD, 'md:EmailAddress', $email ) ); // No "mailto:" prefix.
		if ( '' !== $phone ) {
			$cp->appendChild( XmlSecurity::text_element( $doc, self::NS_MD, 'md:TelephoneNumber', $phone ) );
		}
		return $cp;
	}

	/** Billing ContactPerson with fpa:CessionarioCommittente (private sector, Avviso n.29 v.3). */
	private static function billing_contact( \DOMDocument $doc, array $c ) {
		$f = function ( $tag, $value = null ) use ( $doc ) {
			return null === $value
				? $doc->createElementNS( self::NS_FPA, 'fpa:' . $tag )
				: XmlSecurity::text_element( $doc, self::NS_FPA, 'fpa:' . $tag, $value );
		};

		$id_fiscale = $f( 'IdFiscaleIVA' );
		$id_fiscale->appendChild( $f( 'IdPaese', $c['fpa_id_paese'] ) );
		$id_fiscale->appendChild( $f( 'IdCodice', $c['fpa_id_codice'] ) );

		$anagrafica = $f( 'Anagrafica' );
		$anagrafica->appendChild( $f( 'Denominazione', $c['fpa_denominazione'] ) );

		$dati = $f( 'DatiAnagrafici' );
		$dati->appendChild( $id_fiscale );
		$dati->appendChild( $anagrafica );

		$sede = $f( 'Sede' );
		$sede->appendChild( $f( 'Indirizzo', $c['fpa_indirizzo'] ) );
		$sede->appendChild( $f( 'NumeroCivico', $c['fpa_numero_civico'] ) );
		$sede->appendChild( $f( 'CAP', $c['fpa_cap'] ) );
		$sede->appendChild( $f( 'Comune', $c['fpa_comune'] ) );
		$sede->appendChild( $f( 'Provincia', $c['fpa_provincia'] ) );
		$sede->appendChild( $f( 'Nazione', $c['fpa_nazione'] ) );

		$cc = $f( 'CessionarioCommittente' );
		$cc->appendChild( $dati );
		$cc->appendChild( $sede );

		$cp = $doc->createElementNS( self::NS_MD, 'md:ContactPerson' );
		$cp->setAttribute( 'contactType', 'billing' );
		$ext = $doc->createElementNS( self::NS_MD, 'md:Extensions' );
		$ext->appendChild( $cc );
		$cp->appendChild( $ext );
		$cp->appendChild( XmlSecurity::text_element( $doc, self::NS_MD, 'md:Company', self::first( $c['fpa_org_name'], $c['org_name'] ) ) );
		$cp->appendChild( XmlSecurity::text_element( $doc, self::NS_MD, 'md:EmailAddress', self::first( $c['fpa_email'], $c['contact_email'] ) ) );
		$phone = self::first( $c['fpa_phone'], $c['contact_phone'] );
		if ( '' !== $phone ) {
			$cp->appendChild( XmlSecurity::text_element( $doc, self::NS_MD, 'md:TelephoneNumber', $phone ) );
		}
		return $cp;
	}

	private static function first( $value, $fallback ) {
		$value = trim( (string) $value );
		return '' !== $value ? $value : (string) $fallback;
	}
}
