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

	/**
	 * Prima riga dei file della chiave privata. Se un web server servisse il file senza eseguirlo
	 * si leggerebbe la chiave; eseguendolo (come avviene per qualunque .php) non stampa nulla.
	 * Non e' cifratura: la protezione vera sono i permessi, .htaccess, index.php e il fatto che la
	 * cartella non e' mai elencata. Non si cifra con i salt di WordPress: ruotarli (cosa che si fa
	 * dopo un'intrusione) renderebbe la chiave illeggibile e farebbe perdere la registrazione SPID/CIE.
	 */
	const KEY_GUARD = "<?php exit; ?>\n";

	/**
	 * Cartella di default dei dati: dentro il plugin. NB: l'aggiornamento di un plugin cancella la
	 * sua cartella, vedi \WpSpidCie\Support\DataPreserver che la mette al riparo.
	 *
	 * @return string
	 */
	public static function default_storage_dir() {
		return WPSPID_PLUGIN_DIR . 'data/';
	}

	/**
	 * Get the directory for private keys, certificates and registered metadata.
	 * `WPSPID_PRIVATE_DIR` (wp-config.php) la sposta altrove, per chi puo' usare un percorso privato.
	 *
	 * @return string Absolute path with trailing slash.
	 */
	public static function get_storage_dir() {
		if ( defined( 'WPSPID_PRIVATE_DIR' ) && WPSPID_PRIVATE_DIR ) {
			$dir = trailingslashit( WPSPID_PRIVATE_DIR );
		} else {
			$dir = self::default_storage_dir();
		}

		if ( ! file_exists( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		// Defence in depth (Apache 2.4 and 2.2 syntax; nginx ignores .htaccess, see the PHP guard on keys).
		if ( ! file_exists( $dir . '.htaccess' ) ) {
			file_put_contents(
				$dir . '.htaccess',
				"<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n"
			);
		}
		if ( ! file_exists( $dir . 'index.php' ) ) {
			file_put_contents( $dir . 'index.php', '<?php // Silence is golden.' );
		}
		// Se il plugin vive in un repository git, chiavi e metadata non devono finirci per errore.
		if ( ! file_exists( $dir . '.gitignore' ) ) {
			file_put_contents( $dir . '.gitignore', "*\n!.htaccess\n!index.php\n!.gitignore\n" );
		}

		return $dir;
	}

	/**
	 * Get paths for SPID or CIE cert/key.
	 *
	 * @param string $type 'spid' or 'cie'
	 * @return array
	 */
	public static function get_paths( $type = 'spid' ) {
		$dir = self::get_storage_dir();
		return array(
			'key'  => $dir . $type . '-sp.key.php',
			'cert' => $dir . $type . '-sp.crt',
		);
	}

	/**
	 * Vecchia posizione (chiave in chiaro in uploads/): raggiungibile da web su nginx.
	 *
	 * @return string|null
	 */
	private static function legacy_dir() {
		if ( ( defined( 'WPSPID_PRIVATE_DIR' ) && WPSPID_PRIVATE_DIR ) || ! function_exists( 'wp_upload_dir' ) ) {
			return null;
		}
		$u = wp_upload_dir();
		return empty( $u['basedir'] ) ? null : trailingslashit( $u['basedir'] ) . 'wp-spid-cie-private/';
	}

	/**
	 * Sposta chiave e certificato dalla vecchia posizione (stessa copia, formato nuovo) e cancella la
	 * chiave in chiaro. Non tocca nulla se la coppia non e' coerente.
	 *
	 * @param string $type
	 * @param string $legacy_dir Cartella con {type}-sp.key e {type}-sp.crt.
	 * @return bool True se migrati.
	 */
	public static function migrate_legacy( $type, $legacy_dir ) {
		$legacy_dir = trailingslashit( $legacy_dir );
		$old_key    = $legacy_dir . $type . '-sp.key';
		$old_cert   = $legacy_dir . $type . '-sp.crt';
		if ( ! is_file( $old_key ) || ! is_file( $old_cert ) ) {
			return false;
		}
		$paths = self::get_paths( $type );
		if ( file_exists( $paths['key'] ) ) {
			return false; // Gia' presente nel formato nuovo: non sovrascrivere.
		}
		$key  = file_get_contents( $old_key );
		$cert = file_get_contents( $old_cert );
		$pkey = $key ? openssl_pkey_get_private( $key ) : false;
		$x509 = $cert ? openssl_x509_read( $cert ) : false;
		if ( ! $pkey || ! $x509 || ! openssl_x509_check_private_key( $x509, $pkey ) ) {
			return false;
		}
		self::write_files( $paths, $key, $cert );
		if ( trim( (string) self::get_private_key_raw( $paths['key'] ) ) !== trim( $key ) ) {
			wp_delete_file( $paths['key'] );
			return false;
		}
		wp_delete_file( $old_key );
		wp_delete_file( $old_cert );
		return true;
	}

	/** Migra una sola volta per richiesta, se esiste ancora la vecchia posizione. */
	private static function maybe_migrate( $type ) {
		static $done = array();
		if ( isset( $done[ $type ] ) ) {
			return;
		}
		$done[ $type ] = true;
		$legacy        = self::legacy_dir();
		if ( $legacy && is_file( $legacy . $type . '-sp.key' ) ) {
			self::migrate_legacy( $type, $legacy );
		}
	}

	/**
	 * Check if cert and key exist for a given type.
	 *
	 * @param string $type
	 * @return bool
	 */
	public static function exists( $type = 'spid' ) {
		self::maybe_migrate( $type );
		$paths = self::get_paths( $type );
		return file_exists( $paths['key'] ) && file_exists( $paths['cert'] );
	}

	/**
	 * Get certificate content.
	 *
	 * @param string $type
	 * @return string|false
	 */
	public static function get_certificate( $type = 'spid' ) {
		self::maybe_migrate( $type );
		$paths = self::get_paths( $type );
		if ( file_exists( $paths['cert'] ) ) {
			return file_get_contents( $paths['cert'] );
		}
		return false;
	}

	/**
	 * Get private key content (the PHP guard is stripped).
	 *
	 * @param string $type
	 * @return string|false
	 */
	public static function get_private_key( $type = 'spid' ) {
		self::maybe_migrate( $type );
		$paths = self::get_paths( $type );
		return self::get_private_key_raw( $paths['key'] );
	}

	private static function get_private_key_raw( $file ) {
		if ( ! is_file( $file ) ) {
			return false;
		}
		$content = file_get_contents( $file );
		if ( false === $content ) {
			return false;
		}
		return 0 === strpos( $content, self::KEY_GUARD ) ? substr( $content, strlen( self::KEY_GUARD ) ) : $content;
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
		self::write_files( self::get_paths( $type ), $key_out, $cert_out );
		return true;
	}

	/**
	 * Genera chiave e certificato SENZA scriverli su disco (usato anche dal probe dei requisiti).
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
		chmod( $cnf, 0600 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- permessi restrittivi sulla chiave privata: WP_Filesystem non e' adatto
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

		self::write_files( self::get_paths( $type ), $private_key, $certificate );

		return true;
	}

	/**
	 * Write key/cert with restrictive permissions from the start (no 0644 window for the key).
	 */
	private static function write_files( array $paths, $key_pem, $cert_pem ) {
		$old = umask( 0077 );
		$k   = file_put_contents( $paths['key'], self::KEY_GUARD . $key_pem );
		umask( $old );
		$c = file_put_contents( $paths['cert'], $cert_pem );
		if ( false === $k || false === $c ) {
			throw new \Exception( 'Unable to save the certificate or private key.' );
		}
		chmod( $paths['key'], 0600 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- permessi restrittivi sulla chiave privata: WP_Filesystem non e' adatto
		chmod( $paths['cert'], 0644 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- permessi restrittivi sulla chiave privata: WP_Filesystem non e' adatto
	}
}
