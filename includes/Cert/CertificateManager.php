<?php
// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- i messaggi delle eccezioni non vengono stampati direttamente: chi li mostra li esegue con esc_html().
namespace WpSpidCie\Cert;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages Service Provider X.509 certificates and private keys.
 */
class CertificateManager {

	/** Nome sicuro per l'opzione: solo [a-z0-9_]. */
	private static function type( $type ) {
		return preg_replace( '/[^a-z0-9_]/', '', strtolower( (string) $type ) );
	}

	/** Record salvato ({v, key, cert, saved}) o null. Non avvia la migrazione. */
	public static function record( $type = 'spid' ) {
		$r = Storage::get( 'cert_' . self::type( $type ) );
		return ( $r && isset( $r['key'], $r['cert'] ) ) ? $r : null;
	}

	/**
	 * Salva chiave (cifrata se WPSPID_SECRET e' definita) e certificato, poi li rilegge e verifica.
	 *
	 * @throws \Exception Se non si riesce a salvare o la verifica fallisce (in tal caso il record viene tolto).
	 */
	public static function store( $type, $key_pem, $cert_pem ) {
		$name = 'cert_' . self::type( $type );
		$prev = Storage::get( $name );
		Storage::set( $name, array(
			'v'     => 1,
			'key'   => KeyVault::seal( $key_pem ),
			'cert'  => trim( $cert_pem ) . "\n",
			'saved' => time(),
		) );
		$back = self::record( $type );
		$open = $back ? KeyVault::open( $back['key'] ) : array( 'key' => false );
		$ok   = $back && false !== $open['key'] && trim( $open['key'] ) === trim( $key_pem ) && trim( $back['cert'] ) === trim( $cert_pem );
		if ( ! $ok ) {
			if ( $prev ) {
				Storage::set( $name, $prev );
			} else {
				Storage::delete( $name );
			}
			throw new \Exception( 'Unable to save the certificate or private key.' );
		}
	}

	/** Cancella certificato e chiave dal database. */
	public static function delete( $type ) {
		Storage::delete( 'cert_' . self::type( $type ) );
	}

	/**
	 * Vecchia posizione (chiave in chiaro in uploads/) o cartella data/: vedi Migrator.
	 *
	 * @param string $type
	 * @param string $legacy_dir Cartella con {type}-sp.key e {type}-sp.crt.
	 * @return bool True se migrati nel database.
	 */
	public static function migrate_legacy( $type, $legacy_dir ) {
		return Migrator::migrate_type( self::type( $type ), trailingslashit( $legacy_dir ) . self::type( $type ) . '-sp.key', trailingslashit( $legacy_dir ) . self::type( $type ) . '-sp.crt', false );
	}

	/**
	 * Check if cert and key exist for a given type (anche se la chiave non e' leggibile: vedi key_state()).
	 *
	 * @param string $type
	 * @return bool
	 */
	public static function exists( $type = 'spid' ) {
		Migrator::maybe_run();
		return null !== self::record( $type );
	}

	/**
	 * Get certificate content.
	 *
	 * @param string $type
	 * @return string|false
	 */
	public static function get_certificate( $type = 'spid' ) {
		Migrator::maybe_run();
		$r = self::record( $type );
		return $r ? $r['cert'] : false;
	}

	/**
	 * Stato della chiave privata.
	 *
	 * @return array {status:string (KeyVault::S_*), readable:bool}
	 */
	public static function key_state( $type = 'spid' ) {
		Migrator::maybe_run();
		$r = self::record( $type );
		if ( ! $r ) {
			return array( 'status' => KeyVault::S_MISSING, 'readable' => false );
		}
		$open = KeyVault::open( $r['key'] );
		return array( 'status' => $open['status'], 'readable' => false !== $open['key'] );
	}

	/**
	 * Get private key content, or false if missing/unreadable (never a wrong key).
	 *
	 * @param string $type
	 * @return string|false
	 */
	public static function get_private_key( $type = 'spid' ) {
		Migrator::maybe_run();
		$r = self::record( $type );
		if ( ! $r ) {
			return false;
		}
		$open = KeyVault::open( $r['key'] );
		return $open['key'];
	}

	/**
	 * Chiave privata o eccezione con la causa (cifratura, costante assente/diversa, ...).
	 *
	 * @throws \Exception
	 */
	public static function private_key_or_fail( $type = 'spid' ) {
		$state = self::key_state( $type );
		if ( ! $state['readable'] ) {
			throw new \Exception( KeyVault::message( $state['status'] ) );
		}
		return self::get_private_key( $type );
	}

	/** Salva di nuovo la chiave (cifrandola se ora c'e' WPSPID_SECRET). @throws \Exception */
	public static function reseal( $type = 'spid' ) {
		$cert = self::get_certificate( $type );
		$key  = self::get_private_key( $type );
		if ( ! $cert || ! $key ) {
			throw new \Exception( KeyVault::message( self::key_state( $type )['status'] ) );
		}
		self::store( $type, $key, $cert );
	}

	/**
	 * Generate a self-signed certificate + RSA key, with the subject and extensions required by
	 * the AgID notices (Avviso SPID n.29 v.3): organizationIdentifier, uri, agIDcert and
	 * spid-publicsector/privatesector policies, keyUsage digitalSignature+nonRepudiation.
	 *
	 * The OpenSSL config is static (no user data is ever written into it); subject values are
	 * passed through the DN array.
	 *
	 * @param string $type    'spid' or 'cie'.
	 * @param array  $subject {org_name, common_name, uri, org_identifier, country, locality, public(bool)}
	 * @param int    $days    Validity (default 730, as spid-php).
	 * @return bool
	 * @throws \Exception
	 */
	public static function generate( $type = 'spid', array $subject = array(), $days = 730 ) {
		\WpSpidCie\Support\Requirements::assert_can_generate();

		list( $key_out, $cert_out ) = self::build_material( $type, $subject, $days, 3072 );
		self::store( $type, $key_out, $cert_out );
		return true;
	}

	/**
	 * Genera chiave e certificato SENZA salvarli (usato anche dal probe dei requisiti).
	 *
	 * @param string $type    'spid' or 'cie'.
	 * @param array  $subject Vedi generate().
	 * @param int    $days    Validity.
	 * @param int    $bits    Dimensione della chiave RSA.
	 * @return string[] {private key PEM, certificate PEM}
	 * @throws \Exception
	 */
	public static function build_material( $type, array $subject, $days, $bits = 3072 ) {
		$public = ! isset( $subject['public'] ) || $subject['public'];

		$required = array( 'org_name', 'common_name', 'uri', 'org_identifier', 'country', 'locality' );
		foreach ( $required as $k ) {
			if ( empty( $subject[ $k ] ) ) {
				throw new \Exception( 'Missing data for the certificate: ' . $k );
			}
		}

		$conf = self::openssl_config( 'spid' === $type, $public );
		$cnf  = tempnam( sys_get_temp_dir(), 'wpspid' );
		if ( false === $cnf ) {
			throw new \Exception( 'Unable to create the temporary OpenSSL configuration file.' );
		}
		// tempnam() crea il file con permessi 0600.
		file_put_contents( $cnf, $conf );

		try {
			$config_args = array(
				'config'           => $cnf,
				'private_key_bits' => (int) $bits,
				'private_key_type' => OPENSSL_KEYTYPE_RSA,
				'digest_alg'       => 'sha256',
				'req_extensions'   => 'req_ext',
				'x509_extensions'  => 'req_ext',
			);

			$dn = array(
				'organizationName'       => $subject['org_name'],
				'commonName'             => $subject['common_name'],
				'uri'                    => $subject['uri'],
				'organizationIdentifier' => $subject['org_identifier'],
				'countryName'            => strtoupper( substr( $subject['country'], 0, 2 ) ),
				'localityName'           => $subject['locality'],
			);

			$private_key = openssl_pkey_new( $config_args );
			if ( ! $private_key ) {
				throw new \Exception( 'Generazione chiave privata fallita: ' . openssl_error_string() );
			}
			$csr = openssl_csr_new( $dn, $private_key, $config_args );
			if ( ! $csr ) {
				throw new \Exception( 'Generazione CSR fallita: ' . openssl_error_string() );
			}
			$x509 = openssl_csr_sign( $csr, null, $private_key, (int) $days, $config_args );
			if ( ! $x509 ) {
				throw new \Exception( 'Certificate signing failed: ' . openssl_error_string() );
			}
			openssl_x509_export( $x509, $cert_out );
			openssl_pkey_export( $private_key, $key_out, null, $config_args );
		} finally {
			wp_delete_file( $cnf );
		}

		return array( $key_out, $cert_out );
	}

	/** Static OpenSSL config: no user-controlled text. */
	private static function openssl_config( $is_spid, $public ) {
		$policies = '';
		$oids     = "uri=2.5.4.83\n";
		$ext      = "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n";
		if ( $is_spid ) {
			$oids    .= "agidcert=1.3.76.16.6\nspid-publicsector-SP=1.3.76.16.4.2.1\nspid-privatesector-SP=1.3.76.16.4.3.1\n";
			$ext     .= "certificatePolicies=@agid_policies,@spid_policies\n";
			$policies = "\n[ agid_policies ]\npolicyIdentifier=agidcert\nuserNotice=@agidcert_notice\n"
				. "\n[ agidcert_notice ]\nexplicitText=\"agIDcert\"\n"
				. "\n[ spid_policies ]\npolicyIdentifier=" . ( $public ? 'spid-publicsector-SP' : 'spid-privatesector-SP' ) . "\nuserNotice=@spid_notice\n"
				. "\n[ spid_notice ]\nexplicitText=\"" . ( $public ? 'cert_SP_Pub' : 'cert_SP_Priv' ) . "\"\n";
		}
		return "oid_section = oids\n\n[ req ]\ndefault_bits = 3072\ndefault_md = sha256\ndistinguished_name = dn\nencrypt_key = no\nprompt = no\n"
			. "req_extensions = req_ext\nx509_extensions = req_ext\n\n[ oids ]\n" . $oids . "\n[ dn ]\n\n[ req_ext ]\n" . $ext . $policies;
	}

	/**
	 * Certificate details for the admin page.
	 *
	 * @return array|false {subject, organization_identifier, valid_to (ts), days_left, fingerprint}
	 */
	public static function info( $type = 'spid' ) {
		$pem = self::get_certificate( $type );
		if ( ! $pem ) {
			return false;
		}
		$parsed = openssl_x509_parse( $pem );
		if ( ! $parsed ) {
			return false;
		}
		$subject = isset( $parsed['subject'] ) ? $parsed['subject'] : array();
		return array(
			'subject'                 => isset( $subject['CN'] ) ? $subject['CN'] : '',
			'organization'            => isset( $subject['O'] ) ? $subject['O'] : '',
			'organization_identifier' => isset( $subject['organizationIdentifier'] ) ? $subject['organizationIdentifier'] : '',
			'valid_to'                => (int) $parsed['validTo_time_t'],
			'days_left'               => (int) floor( ( $parsed['validTo_time_t'] - time() ) / 86400 ),
			'fingerprint'             => openssl_x509_fingerprint( $pem, 'sha256' ),
		);
	}

	/**
	 * Import existing certificate and private key (for migration).
	 *
	 * @param string $type
	 * @param string $private_key
	 * @param string $certificate
	 * @return bool
	 * @throws \Exception
	 */
	public static function import( $type, $private_key, $certificate ) {
		// Validate key and cert
		$pkey = openssl_pkey_get_private( $private_key );
		if ( ! $pkey ) {
			throw new \Exception( 'Invalid private key.' );
		}
		$cert = openssl_x509_read( $certificate );
		if ( ! $cert ) {
			throw new \Exception( 'Invalid certificate.' );
		}

		if ( ! openssl_x509_check_private_key( $cert, $pkey ) ) {
			throw new \Exception( 'The private key does not match the certificate.' );
		}

		self::store( $type, $private_key, $certificate );

		return true;
	}
}
