<?php
// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- i messaggi delle eccezioni non vengono stampati direttamente: chi li mostra li esegue con esc_html().
namespace WpSpidCie\Support;

use WpSpidCie\Cert\CertificateManager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Requisiti del server, con una verifica *pratica* di OpenSSL.
 *
 * Il plugin usa l'estensione PHP `openssl` (non il comando `openssl`), quindi non serve exec().
 * Su un hosting condiviso però l'estensione può esserci e il resto non funzionare: funzioni in
 * `disable_functions`, cartella temporanea non scrivibile, build di OpenSSL che rifiuta gli OID
 * dell'Avviso SPID. Per questo `probe()` prova davvero a generare chiave, CSR e certificato
 * (SPID e CIE) con le stesse impostazioni del plugin, e il risultato blocca generazione e login.
 */
class Requirements {

	const TRANSIENT = 'wpspid_probe';

	const EXTENSIONS = array( 'openssl', 'dom', 'libxml', 'mbstring' );

	/** Funzioni OpenSSL usate dal plugin per generare, firmare e verificare. */
	const FUNCTIONS = array(
		'openssl_pkey_new',
		'openssl_pkey_export',
		'openssl_pkey_get_private',
		'openssl_pkey_get_public',
		'openssl_csr_new',
		'openssl_csr_sign',
		'openssl_x509_export',
		'openssl_x509_parse',
		'openssl_x509_read',
		'openssl_x509_check_private_key',
		'openssl_x509_fingerprint',
		'openssl_sign',
		'openssl_verify',
		'openssl_error_string',
	);

	/**
	 * Solo per i test: sostituisce l'ambiente reale (chiavi: extensions, functions, tmp_writable).
	 *
	 * @var array
	 */
	public static $env = array();

	private static function loaded( $ext, array $env ) {
		$env = $env + self::$env;
		return isset( $env['extensions'] ) ? in_array( $ext, $env['extensions'], true ) : extension_loaded( $ext );
	}

	private static function available( $fn, array $env ) {
		$env = $env + self::$env;
		if ( isset( $env['functions'] ) ) {
			return in_array( $fn, $env['functions'], true );
		}
		if ( ! function_exists( $fn ) ) {
			return false;
		}
		$disabled = array_map( 'trim', explode( ',', (string) ini_get( 'disable_functions' ) ) );
		return ! in_array( $fn, $disabled, true );
	}

	private static function tmp_writable( array $env ) {
		$env = $env + self::$env;
		return isset( $env['tmp_writable'] ) ? (bool) $env['tmp_writable'] : wp_is_writable( sys_get_temp_dir() );
	}

	/**
	 * Controlli economici (nessuna generazione di chiavi).
	 *
	 * @param array $env Override per i test.
	 * @return string[] Error messages (translated).
	 */
	public static function check( array $env = array() ) {
		$errors = array();
		foreach ( self::EXTENSIONS as $ext ) {
			if ( ! self::loaded( $ext, $env ) ) {
				$errors[] = sprintf( /* translators: %s: PHP extension name. */ __( 'The PHP extension "%s" is required.', 'auth-spid-cie' ), $ext );
			}
		}
		if ( self::loaded( 'openssl', $env ) ) {
			$missing = array();
			foreach ( self::FUNCTIONS as $fn ) {
				if ( ! self::available( $fn, $env ) ) {
					$missing[] = $fn;
				}
			}
			if ( $missing ) {
				$errors[] = sprintf( /* translators: %s: list of function names. */ __( 'OpenSSL functions not available (possibly disabled by the host with disable_functions): %s.', 'auth-spid-cie' ), implode( ', ', $missing ) );
			}
		}
		return $errors;
	}

	/**
	 * Verifica pratica: prova a generare chiavi e certificati. Salva il risultato (12 ore).
	 *
	 * @param bool  $force Ignora la cache.
	 * @param array $env   Override per i test.
	 * @return array {ok:bool, errors:string[], openssl_version:string, checked_at:int}
	 */
	public static function probe( $force = false, array $env = array() ) {
		if ( ! $force ) {
			$cached = self::cached();
			if ( null !== $cached ) {
				return $cached;
			}
		}

		$errors = self::check( $env );

		if ( ! $errors && ! self::tmp_writable( $env ) ) {
			$errors[] = sprintf( /* translators: %s: temporary folder path. */ __( 'The PHP temporary folder (%s) is not writable: OpenSSL needs it for its configuration.', 'auth-spid-cie' ), sys_get_temp_dir() );
		}

		if ( ! $errors ) {
			$dir = CertificateManager::get_storage_dir();
			if ( ! is_dir( $dir ) || ! wp_is_writable( $dir ) ) {
				$errors[] = sprintf( /* translators: %s: folder path. */ __( 'The plugin data folder is not writable: %s', 'auth-spid-cie' ), $dir );
			}
		}

		if ( ! $errors ) {
			$subject = array(
				'org_name'       => 'Probe',
				'common_name'    => 'Probe',
				'uri'            => 'https://probe.invalid',
				'org_identifier' => 'PA:IT-probe',
				'country'        => 'IT',
				'locality'       => 'Roma',
				'public'         => true,
			);
			foreach ( array( 'spid', 'cie' ) as $type ) {
				try {
					// 2048 bit: stessa configurazione OpenSSL del plugin ma molto più veloce di 3072.
					$m = CertificateManager::build_material( $type, $subject, 1, 2048 );
					if ( ! openssl_x509_parse( $m[1] ) ) {
						$errors[] = sprintf( /* translators: %s: SPID or CIE. */ __( 'Test certificate not readable (%s).', 'auth-spid-cie' ), strtoupper( $type ) );
					}
				} catch ( \Throwable $e ) {
					$errors[] = sprintf( /* translators: 1: SPID or CIE, 2: technical error message. */ __( 'Test generation for %1$s failed: %2$s', 'auth-spid-cie' ), strtoupper( $type ), $e->getMessage() );
				}
			}
		}

		$result = array(
			'ok'              => ! $errors,
			'errors'          => $errors,
			'openssl_version' => defined( 'OPENSSL_VERSION_TEXT' ) ? OPENSSL_VERSION_TEXT : '',
			'checked_at'      => time(),
		);
		if ( function_exists( 'set_transient' ) ) {
			set_transient( self::TRANSIENT, $result, 12 * 3600 );
		}
		return $result;
	}

	/** Ultimo risultato in cache, o null. */
	public static function cached() {
		if ( ! function_exists( 'get_transient' ) ) {
			return null;
		}
		$r = get_transient( self::TRANSIENT );
		return is_array( $r ) && isset( $r['ok'] ) ? $r : null;
	}

	/**
	 * Blocca la generazione dei certificati se l'ambiente non è idoneo (controllo economico).
	 *
	 * @throws \Exception
	 */
	public static function assert_can_generate() {
		$errors = self::check();
		if ( $errors ) {
			throw new \Exception( 'The server does not allow generating certificates: ' . implode( ' ', $errors ) );
		}
	}
}
