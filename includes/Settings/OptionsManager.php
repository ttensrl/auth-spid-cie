<?php
namespace WpSpidCie\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Schema, defaults and sanitization of the plugin options (`wpspid_options`).
 *
 * The fields mirror what the spid-cie-php setup asks for (see the SPID technical rules).
 */
class OptionsManager {

	const OPTION = 'wpspid_options';

	/** All SPID attributes with the default selection of spid-php (+ label). */
	public static function attributes_catalog() {
		return array(
			'spidCode'             => array( __( 'SPID identification code', 'auth-spid-cie' ), false ),
			'name'                 => array( __( 'First name', 'auth-spid-cie' ), true ),
			'familyName'           => array( __( 'Last name', 'auth-spid-cie' ), true ),
			'placeOfBirth'         => array( __( 'Place of birth', 'auth-spid-cie' ), false ),
			'countyOfBirth'        => array( __( 'County of birth', 'auth-spid-cie' ), false ),
			'dateOfBirth'          => array( __( 'Date of birth', 'auth-spid-cie' ), true ),
			'gender'               => array( __( 'Gender', 'auth-spid-cie' ), false ),
			'companyName'          => array( __( 'Company name', 'auth-spid-cie' ), false ),
			'registeredOffice'     => array( __( 'Registered office', 'auth-spid-cie' ), false ),
			'fiscalNumber'         => array( __( 'Tax code', 'auth-spid-cie' ), true ),
			'ivaCode'              => array( __( 'VAT number', 'auth-spid-cie' ), false ),
			'idCard'               => array( __( 'ID document', 'auth-spid-cie' ), false ),
			'expirationDate'       => array( __( 'Document expiry date', 'auth-spid-cie' ), false ),
			'mobilePhone'          => array( __( 'Mobile phone', 'auth-spid-cie' ), false ),
			'email'                => array( __( 'Email', 'auth-spid-cie' ), true ),
			'address'              => array( __( 'Residential address', 'auth-spid-cie' ), false ),
			'digitalAddress'       => array( __( 'PEC / digital domicile', 'auth-spid-cie' ), false ),
			'domicileStreetAddress' => array( __( 'Domicile: street', 'auth-spid-cie' ), false ),
			'domicilePostalCode'   => array( __( 'Domicile: postal code', 'auth-spid-cie' ), false ),
			'domicileMunicipality' => array( __( 'Domicile: municipality', 'auth-spid-cie' ), false ),
			'domicileProvince'     => array( __( 'Domicile: province', 'auth-spid-cie' ), false ),
			'domicileNation'       => array( __( 'Domicile: country', 'auth-spid-cie' ), false ),
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
				self::error( 'entity_id', __( 'The entityID must be a URL starting with https://', 'auth-spid-cie' ) );
			}
		}
		if ( array_key_exists( 'org_url', $input ) ) {
			$url = trim( (string) $input['org_url'] );
			if ( '' === $url || self::is_https_url( $url ) || self::is_http_url( $url ) ) {
				$out['org_url'] = $url;
			} else {
				self::error( 'org_url', __( 'The organization URL is not valid.', 'auth-spid-cie' ) );
			}
		}

		foreach ( array( 'contact_email', 'fpa_email' ) as $key ) {
			if ( array_key_exists( $key, $input ) ) {
				$mail = function_exists( 'sanitize_email' ) ? sanitize_email( $input[ $key ] ) : trim( (string) $input[ $key ] );
				if ( '' !== trim( (string) $input[ $key ] ) && ( '' === $mail || ! filter_var( $mail, FILTER_VALIDATE_EMAIL ) ) ) {
					self::error( $key, __( 'Invalid email address.', 'auth-spid-cie' ) );
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
					self::error( 'test_idp_urls', sprintf( /* translators: %s: the ignored URL. */ __( 'Metadata URL ignored (https:// required): %s', 'auth-spid-cie' ), $line ) );
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
				self::error( 'test_idp_xml', __( 'The pasted XML metadata is too large.', 'auth-spid-cie' ) );
			} elseif ( null === \WpSpidCie\Idp\IdpMetadata::parse( $xml ) ) {
				self::error( 'test_idp_xml', __( 'The pasted XML metadata is not valid (entityID, signing certificate and SingleSignOnService are required).', 'auth-spid-cie' ) );
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
			'org_name'      => __( 'Organization name', 'auth-spid-cie' ),
			'org_display_name' => __( 'Display name', 'auth-spid-cie' ),
			'org_url'       => __( 'Organization URL', 'auth-spid-cie' ),
			'org_code'      => 'public' === $o['sp_type'] ? __( 'IPA code', 'auth-spid-cie' ) : ( 'FiscalCode' === $o['org_code_type'] ? __( 'Tax code', 'auth-spid-cie' ) : __( 'VAT number', 'auth-spid-cie' ) ),
			'locality'      => __( 'Locality', 'auth-spid-cie' ),
			'contact_email' => __( 'Contact email', 'auth-spid-cie' ),
			'contact_phone' => __( 'Contact phone', 'auth-spid-cie' ),
		);
		if ( 'cie' === $service || 'private' === $o['sp_type'] ) {
			$need['cie_fiscal_code'] = 'cie' === $service ? __( 'Tax code (CIE)', 'auth-spid-cie' ) : null;
		}
		foreach ( $need as $key => $label ) {
			if ( null !== $label && '' === trim( (string) $o[ $key ] ) ) {
				$missing[] = $label;
			}
		}
		if ( 'cie' === $service ) {
			foreach ( array( 'cie_nace2' => __( 'ATECO / NACE2 code', 'auth-spid-cie' ), 'cie_municipality' => __( 'Municipality ISTAT code', 'auth-spid-cie' ), 'cie_province' => __( 'Province code', 'auth-spid-cie' ) ) as $key => $label ) {
				if ( '' === trim( (string) $o[ $key ] ) ) {
					$missing[] = $label;
				}
			}
		}
		if ( 'spid' === $service && 'private' === $o['sp_type'] ) {
			foreach ( array(
				'fpa_id_codice' => __( 'Billing: IdCodice', 'auth-spid-cie' ), 'fpa_denominazione' => __( 'Billing: company name', 'auth-spid-cie' ),
				'fpa_indirizzo' => __( 'Billing: address', 'auth-spid-cie' ), 'fpa_numero_civico' => __( 'Billing: street number', 'auth-spid-cie' ),
				'fpa_cap' => __( 'Billing: postal code', 'auth-spid-cie' ), 'fpa_comune' => __( 'Billing: municipality', 'auth-spid-cie' ),
				'fpa_provincia' => __( 'Billing: province', 'auth-spid-cie' ), 'fpa_org_name' => __( 'Billing: legal name', 'auth-spid-cie' ),
				'fpa_email' => __( 'Billing: email', 'auth-spid-cie' ), 'fpa_phone' => __( 'Billing: phone', 'auth-spid-cie' ),
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
		$value = function_exists( 'sanitize_text_field' ) ? sanitize_text_field( $value ) : trim( wp_strip_all_tags( $value ) );
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
