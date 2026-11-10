<?php
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
		return isset( $env['tmp_writable'] ) ? (bool) $env['tmp_writable'] : is_writable( sys_get_temp_dir() );
	}

	/**
	 * Controlli economici (nessuna generazione di chiavi).
	 *
	 * @param array $env Override per i test.
	 * @return string[] Errori, in italiano.
	 */
	public static function check( array $env = array() ) {
		$errors = array();
		foreach ( self::EXTENSIONS as $ext ) {
			if ( ! self::loaded( $ext, $env ) ) {
				$errors[] = sprintf( 'L\'estensione PHP "%s" è richiesta.', $ext );
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
				$errors[] = 'Funzioni OpenSSL non disponibili (forse disattivate dall\'hosting con disable_functions): ' . implode( ', ', $missing ) . '.';
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
			$errors[] = 'La cartella temporanea di PHP (' . sys_get_temp_dir() . ') non è scrivibile: OpenSSL ne ha bisogno per la configurazione.';
		}

		if ( ! $errors ) {
			$dir = CertificateManager::get_storage_dir();
			if ( ! is_dir( $dir ) || ! is_writable( $dir ) ) {
				$errors[] = 'La cartella dei dati del plugin non è scrivibile: ' . $dir;
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
						$errors[] = 'Certificato di prova non leggibile (' . strtoupper( $type ) . ').';
					}
				} catch ( \Throwable $e ) {
					$errors[] = 'Generazione di prova ' . strtoupper( $type ) . ' non riuscita: ' . $e->getMessage();
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
			throw new \Exception( 'Il server non permette di generare certificati: ' . implode( ' ', $errors ) );
		}
	}
}
