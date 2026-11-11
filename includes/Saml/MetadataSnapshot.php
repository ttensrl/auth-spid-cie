<?php
namespace AuthSpidCie\Saml;

use AuthSpidCie\Cert\Storage;
use AuthSpidCie\Xml\XmlSecurity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Il metadata che e' stato effettivamente registrato presso AgID/CIE.
 *
 * Il plugin genera il metadata al volo dalle impostazioni, quindi non c'e' un file "sorgente". Ma
 * la registrazione richiede che resti stabile: cambiare ragione sociale, contatti o certificato
 * senza ripetere la registrazione rompe l'adesione. Qui si salva una copia di cio' che e' stato
 * registrato e si segnala quando il metadata attuale e' diverso.
 *
 * Il confronto e' fatto sul metadata normalizzato: ID casuale, validUntil e firma cambiano a ogni
 * generazione e non devono contare.
 */
class MetadataSnapshot {

	const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

	private static function service( $service ) {
		return 'cie' === $service ? 'cie' : 'spid';
	}

	private static function name( $service ) {
		return 'registered_' . self::service( $service );
	}

	/**
	 * @param string $xml Metadata.
	 * @return string XML canonico senza firma, ID e validUntil.
	 * @throws \Exception Se non e' un EntityDescriptor SAML ben formato.
	 */
	public static function normalize( $xml ) {
		$doc  = XmlSecurity::load_xml( $xml );
		$root = $doc->documentElement;
		if ( ! $root || 'EntityDescriptor' !== $root->localName ) {
			throw new \Exception( 'Not a SAML metadata document (EntityDescriptor missing).' );
		}
		$xp = new \DOMXPath( $doc );
		$xp->registerNamespace( 'ds', self::NS_DS );
		foreach ( iterator_to_array( $xp->query( '//ds:Signature' ) ) as $sig ) {
			$sig->parentNode->removeChild( $sig );
		}
		$root->removeAttribute( 'ID' );
		$root->removeAttribute( 'validUntil' );
		return $doc->C14N( true, false );
	}

	public static function fingerprint( $xml ) {
		return hash( 'sha256', self::normalize( $xml ) );
	}

	/**
	 * Salva il metadata come "registrato".
	 *
	 * @param string $service 'spid' o 'cie'.
	 * @param string $xml     Metadata (firmato) appena generato.
	 * @param string $note    Nota libera, es. "registrato su AgID il ...".
	 * @return array Meta salvato.
	 * @throws \Exception
	 */
	public static function save( $service, $xml, $note = '' ) {
		$fp    = self::fingerprint( $xml ); // Valida anche che sia metadata.
		$doc   = XmlSecurity::load_xml( $xml );
		$meta  = array(
			'sha256'    => $fp,
			'saved_at'  => gmdate( 'c' ),
			'note'      => (string) $note,
			'entity_id' => $doc->documentElement->getAttribute( 'entityID' ),
		);
		self::store_raw( $service, $xml, $meta );
		return $meta;
	}

	/** Salva xml e meta cosi' come sono (usato anche dalla migrazione). */
	public static function store_raw( $service, $xml, array $meta ) {
		Storage::set( self::name( $service ), array( 'xml' => (string) $xml, 'meta' => $meta ) );
	}

	public static function delete( $service ) {
		Storage::delete( self::name( $service ) );
	}

	/** @return array|null {sha256, saved_at, note, entity_id, xml} */
	public static function get( $service ) {
		\AuthSpidCie\Cert\Migrator::maybe_run();
		$r = Storage::get( self::name( $service ) );
		if ( ! $r || empty( $r['xml'] ) || ! is_array( $r['meta'] ?? null ) || empty( $r['meta']['sha256'] ) ) {
			return null;
		}
		$meta        = $r['meta'];
		$meta['xml'] = (string) $r['xml'];
		return $meta;
	}

	/**
	 * @param string $service
	 * @param string $current_xml Metadata generato adesso.
	 * @return array {state: none|same|changed, saved_at, note}
	 */
	public static function status( $service, $current_xml ) {
		$saved = self::get( $service );
		if ( ! $saved ) {
			return array( 'state' => 'none', 'saved_at' => '', 'note' => '' );
		}
		return array(
			'state'    => hash_equals( $saved['sha256'], self::fingerprint( $current_xml ) ) ? 'same' : 'changed',
			'saved_at' => $saved['saved_at'],
			'note'     => $saved['note'],
		);
	}
}

/** wp_json_encode non esiste nei test senza WordPress. */
function wp_json_encode_compat( $data ) {
	return function_exists( 'wp_json_encode' ) ? wp_json_encode( $data ) : json_encode( $data );
}
