<?php
namespace WpSpidCie\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Schema, defaults and sanitization of the plugin options (`wpspid_options`).
 *
 * The fields mirror what the spid-cie-php setup asks for (see ANALISI_E_ISTRUZIONI.md §4.5/§4.7).
 */
class OptionsManager {

	const OPTION = 'wpspid_options';

	/** All SPID attributes with the default selection of spid-php (+ label). */
	public static function attributes_catalog() {
		return array(
			'spidCode'             => array( 'Codice identificativo SPID', false ),
			'name'                 => array( 'Nome', true ),
			'familyName'           => array( 'Cognome', true ),
			'placeOfBirth'         => array( 'Luogo di nascita', false ),
			'countyOfBirth'        => array( 'Provincia di nascita', false ),
			'dateOfBirth'          => array( 'Data di nascita', true ),
			'gender'               => array( 'Sesso', false ),
			'companyName'          => array( 'Ragione sociale', false ),
			'registeredOffice'     => array( 'Sede legale', false ),
			'fiscalNumber'         => array( 'Codice fiscale', true ),
			'ivaCode'              => array( 'Partita IVA', false ),
			'idCard'               => array( 'Documento d\'identità', false ),
			'expirationDate'       => array( 'Scadenza documento', false ),
			'mobilePhone'          => array( 'Telefono cellulare', false ),
			'email'                => array( 'Email', true ),
			'address'              => array( 'Indirizzo di residenza', false ),
			'digitalAddress'       => array( 'PEC / domicilio digitale', false ),
			'domicileStreetAddress' => array( 'Domicilio: via', false ),
			'domicilePostalCode'   => array( 'Domicilio: CAP', false ),
			'domicileMunicipality' => array( 'Domicilio: comune', false ),
			'domicileProvince'     => array( 'Domicilio: provincia', false ),
			'domicileNation'       => array( 'Domicilio: nazione', false ),
		);
	}

	public static function default_attributes() {
		$out = array();
		foreach ( self::attributes_catalog() as $name => $def ) {
			if ( $def[1] ) {
				$out[] = $name;
			}
		}
		return $out;
	}

	public static function defaults() {
		return array(
			// General.
			'enabled'           => false,
			'production'        => false,
			'spid_enabled'      => true,
			'cie_enabled'       => true,
			'cie_level'         => 2,
			// Service Provider.
			'entity_id'         => '',
			'sp_type'           => 'public', // public|private.
			'sp_name'           => '',
			'sp_description'    => '',
			'org_name'          => '',
			'org_display_name'  => '',
			'org_url'           => '',
			'org_code_type'     => 'IPACode', // IPACode (public) | VATNumber | FiscalCode (private).
			'org_code'          => '',
			'country'           => 'IT',
			'locality'          => '',
			'contact_email'     => '',
			'contact_phone'     => '',
			// Private sector billing contact (Avviso SPID n.29 v.3).
			'fpa_id_paese'      => 'IT',
			'fpa_id_codice'     => '',
			'fpa_denominazione' => '',
			'fpa_indirizzo'     => '',
			'fpa_numero_civico' => '',
			'fpa_cap'           => '',
			'fpa_comune'        => '',
			'fpa_provincia'     => '',
			'fpa_nazione'       => 'IT',
			'fpa_org_name'      => '',
			'fpa_email'         => '',
			'fpa_phone'         => '',
			// CIE extensions.
			'cie_fiscal_code'   => '',
			'cie_nace2'         => '',
			'cie_municipality'  => '', // ISTAT code.
			'cie_province'      => '',
			// SAML.
			'acs_index'         => 0,
			'attributes'        => self::default_attributes(),
			'destination_mode'  => 'entity_id',
			// Test identity providers (non-production only).
			'test_demo'            => true,
			'test_demo_validator'  => false,
			'test_validator'       => false,
			'test_insecure_tls'    => false,
			'test_idp_urls'        => array(),
			'test_idp_xml'         => '',
		);
	}

	private static $bools = array(
		'enabled', 'production', 'spid_enabled', 'cie_enabled',
		'test_demo', 'test_demo_validator', 'test_validator', 'test_insecure_tls',
	);

	private static $texts = array(
		'sp_name', 'sp_description', 'org_name', 'org_display_name', 'locality',
		'fpa_denominazione', 'fpa_indirizzo', 'fpa_numero_civico', 'fpa_comune', 'fpa_org_name',
	);

	/**
	 * Sanitize and validate. Keys absent from $input keep their stored value, except
	 * the checkboxes when the admin form is submitted (marker `_form`).
	 *
	 * @param mixed $input Raw input.
	 * @return array
	 */
	public static function sanitize( $input ) {
		$input    = is_array( $input ) ? $input : array();
		$stored   = function_exists( 'get_option' ) ? get_option( self::OPTION, array() ) : array();
		$out      = array_merge( self::defaults(), is_array( $stored ) ? $stored : array() );
		$is_form  = ! empty( $input['_form'] );

		foreach ( self::$bools as $key ) {
			if ( array_key_exists( $key, $input ) || $is_form ) {
				$out[ $key ] = ! empty( $input[ $key ] );
			}
		}

		foreach ( self::$texts as $key ) {
			if ( array_key_exists( $key, $input ) ) {
				$out[ $key ] = self::text( $input[ $key ] );
			}
		}

		if ( array_key_exists( 'cie_level', $input ) ) {
			$out['cie_level'] = max( 1, min( 3, (int) $input['cie_level'] ) );
		}
		if ( array_key_exists( 'acs_index', $input ) ) {
			$out['acs_index'] = max( 0, min( 99, (int) $input['acs_index'] ) );
		}
		if ( array_key_exists( 'sp_type', $input ) ) {
			$out['sp_type'] = ( 'private' === $input['sp_type'] ) ? 'private' : 'public';
		}
		if ( array_key_exists( 'destination_mode', $input ) ) {
			$out['destination_mode'] = ( 'sso_url' === $input['destination_mode'] ) ? 'sso_url' : 'entity_id';
		}

		// Organization code: type depends on the sector.
		if ( 'public' === $out['sp_type'] ) {
			$out['org_code_type'] = 'IPACode';
		} elseif ( array_key_exists( 'org_code_type', $input ) ) {
			$out['org_code_type'] = ( 'FiscalCode' === $input['org_code_type'] ) ? 'FiscalCode' : 'VATNumber';
		} elseif ( ! in_array( $out['org_code_type'], array( 'VATNumber', 'FiscalCode' ), true ) ) {
			$out['org_code_type'] = 'VATNumber';
		}
		if ( array_key_exists( 'org_code', $input ) ) {
			$out['org_code'] = preg_replace( '/[^A-Za-z0-9_\-]/', '', self::text( $input['org_code'] ) );
		}

		// entityID must be an https URL (spid-php rule); keep the previous value otherwise.
		if ( array_key_exists( 'entity_id', $input ) ) {
			$eid = trim( (string) $input['entity_id'] );
			if ( '' === $eid ) {
				$out['entity_id'] = '';
			} elseif ( self::is_https_url( $eid ) ) {
				$out['entity_id'] = $eid;
			} else {
				self::error( 'entity_id', 'L\'entityID deve essere un URL che inizia con https://' );
			}
		}
		if ( array_key_exists( 'org_url', $input ) ) {
			$url = trim( (string) $input['org_url'] );
			if ( '' === $url || self::is_https_url( $url ) || self::is_http_url( $url ) ) {
				$out['org_url'] = $url;
			} else {
				self::error( 'org_url', 'L\'URL dell\'organizzazione non è valido.' );
			}
		}

		foreach ( array( 'contact_email', 'fpa_email' ) as $key ) {
			if ( array_key_exists( $key, $input ) ) {
				$mail = function_exists( 'sanitize_email' ) ? sanitize_email( $input[ $key ] ) : trim( (string) $input[ $key ] );
				if ( '' !== trim( (string) $input[ $key ] ) && ( '' === $mail || ! filter_var( $mail, FILTER_VALIDATE_EMAIL ) ) ) {
					self::error( $key, 'Indirizzo email non valido.' );
				} else {
					$out[ $key ] = $mail;
				}
			}
		}
		foreach ( array( 'contact_phone', 'fpa_phone' ) as $key ) {
			if ( array_key_exists( $key, $input ) ) {
				$out[ $key ] = preg_replace( '/[^0-9+ ]/', '', (string) $input[ $key ] );
			}
		}

		// Short codes.
		$codes = array(
			'country'         => array( '/[^A-Z]/', 2, true ),
			'fpa_id_paese'    => array( '/[^A-Z]/', 2, true ),
			'fpa_nazione'     => array( '/[^A-Z]/', 2, true ),
			'fpa_provincia'   => array( '/[^A-Z]/', 2, true ),
			'cie_province'    => array( '/[^A-Z]/', 2, true ),
			'fpa_cap'         => array( '/[^0-9]/', 5, false ),
			'cie_municipality' => array( '/[^A-Za-z0-9]/', 6, false ),
			'cie_nace2'       => array( '/[^0-9.]/', 8, false ),
			'cie_fiscal_code' => array( '/[^A-Z0-9]/', 16, true ),
			'fpa_id_codice'   => array( '/[^A-Z0-9]/', 28, true ),
		);
		foreach ( $codes as $key => $rule ) {
			if ( array_key_exists( $key, $input ) ) {
				$v = (string) $input[ $key ];
				if ( $rule[2] ) {
					$v = strtoupper( $v );
				}
				$out[ $key ] = substr( preg_replace( $rule[0], '', $v ), 0, $rule[1] );
			}
		}

		// Requested attributes: only known ones; fiscalNumber is always requested (it identifies the citizen).
		if ( array_key_exists( 'attributes', $input ) || $is_form ) {
			$wanted = isset( $input['attributes'] ) && is_array( $input['attributes'] ) ? $input['attributes'] : array();
			$known  = array_keys( self::attributes_catalog() );
			$attrs  = array_values( array_intersect( $known, $wanted ) );
			if ( ! in_array( 'fiscalNumber', $attrs, true ) ) {
				$attrs[] = 'fiscalNumber';
			}
			$out['attributes'] = $attrs;
		}

		// Extra test IdP metadata URLs (one per line, https only, max 5).
		if ( array_key_exists( 'test_idp_urls', $input ) ) {
			$lines = is_array( $input['test_idp_urls'] ) ? $input['test_idp_urls'] : preg_split( '/\r\n|\r|\n/', (string) $input['test_idp_urls'] );
			$urls  = array();
			foreach ( $lines as $line ) {
				$line = trim( $line );
				if ( '' === $line ) {
					continue;
				}
				if ( self::is_https_url( $line ) ) {
					$urls[] = $line;
				} else {
					self::error( 'test_idp_urls', 'URL di metadata ignorato (serve https://): ' . $line );
				}
			}
			$out['test_idp_urls'] = array_slice( array_values( array_unique( $urls ) ), 0, 5 );
		}

		// Pasted IdP metadata XML (e.g. spid-saml-check / spid-sp-test fake IdP), for local testing.
		if ( array_key_exists( 'test_idp_xml', $input ) ) {
			$xml = trim( (string) $input['test_idp_xml'] );
			if ( '' === $xml ) {
				$out['test_idp_xml'] = '';
			} elseif ( strlen( $xml ) > 102400 ) {
				self::error( 'test_idp_xml', 'Il metadata XML incollato è troppo grande.' );
			} elseif ( null === \WpSpidCie\Idp\IdpMetadata::parse( $xml ) ) {
				self::error( 'test_idp_xml', 'Il metadata XML incollato non è valido (servono entityID, certificato di firma e SingleSignOnService).' );
			} else {
				$out['test_idp_xml'] = $xml;
			}
		}

		return $out;
	}

	/**
	 * What is still missing to publish valid metadata for a service. Used by the admin status box.
	 *
	 * @param array  $o       Options (merged with defaults).
	 * @param string $service 'spid' or 'cie'.
	 * @return string[] Human-readable list of missing items.
	 */
	public static function missing_for_metadata( array $o, $service ) {
		$o       = array_merge( self::defaults(), $o );
		$missing = array();
		$need    = array(
			'entity_id'     => 'entityID',
			'org_name'      => 'Nome organizzazione',
			'org_display_name' => 'Nome visualizzato',
			'org_url'       => 'URL organizzazione',
			'org_code'      => 'public' === $o['sp_type'] ? 'Codice IPA' : ( 'FiscalCode' === $o['org_code_type'] ? 'Codice fiscale' : 'Partita IVA' ),
			'locality'      => 'Località',
			'contact_email' => 'Email di contatto',
			'contact_phone' => 'Telefono di contatto',
		);
		if ( 'cie' === $service || 'private' === $o['sp_type'] ) {
			$need['cie_fiscal_code'] = 'cie' === $service ? 'Codice fiscale (CIE)' : null;
		}
		foreach ( $need as $key => $label ) {
			if ( null !== $label && '' === trim( (string) $o[ $key ] ) ) {
				$missing[] = $label;
			}
		}
		if ( 'cie' === $service ) {
			foreach ( array( 'cie_nace2' => 'Codice ATECO/NACE2', 'cie_municipality' => 'Codice ISTAT del comune', 'cie_province' => 'Sigla provincia' ) as $key => $label ) {
				if ( '' === trim( (string) $o[ $key ] ) ) {
					$missing[] = $label;
				}
			}
		}
		if ( 'spid' === $service && 'private' === $o['sp_type'] ) {
			foreach ( array(
				'fpa_id_codice' => 'Fatturazione: IdCodice', 'fpa_denominazione' => 'Fatturazione: denominazione',
				'fpa_indirizzo' => 'Fatturazione: indirizzo', 'fpa_numero_civico' => 'Fatturazione: numero civico',
				'fpa_cap' => 'Fatturazione: CAP', 'fpa_comune' => 'Fatturazione: comune',
				'fpa_provincia' => 'Fatturazione: provincia', 'fpa_org_name' => 'Fatturazione: ragione sociale',
				'fpa_email' => 'Fatturazione: email', 'fpa_phone' => 'Fatturazione: telefono',
			) as $key => $label ) {
				if ( '' === trim( (string) $o[ $key ] ) ) {
					$missing[] = $label;
				}
			}
		}
		return $missing;
	}

	private static function text( $value ) {
		$value = is_scalar( $value ) ? (string) $value : '';
		$value = function_exists( 'sanitize_text_field' ) ? sanitize_text_field( $value ) : trim( strip_tags( $value ) );
		return $value;
	}

	private static function is_https_url( $url ) {
		return 0 === strpos( $url, 'https://' ) && false !== filter_var( $url, FILTER_VALIDATE_URL );
	}

	private static function is_http_url( $url ) {
		return 0 === strpos( $url, 'http://' ) && false !== filter_var( $url, FILTER_VALIDATE_URL );
	}

	private static function error( $code, $message ) {
		if ( function_exists( 'add_settings_error' ) ) {
			add_settings_error( self::OPTION, 'wpspid_' . $code, $message, 'error' );
		}
	}
}
