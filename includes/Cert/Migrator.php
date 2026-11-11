<?php
namespace WpSpidCie\Cert;

use WpSpidCie\Saml\MetadataSnapshot;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Sposta nel database i dati che le versioni precedenti tenevano in file:
 * - `plugins/auth-spid-cie/data/` (chiave `{tipo}-sp.key.php` con guard, certificato `{tipo}-sp.crt`,
 *   metadata registrato `registered-{spid|cie}.xml/.json`);
 * - la vecchissima cartella `uploads/wp-spid-cie-private/` (`{tipo}-sp.key` in chiaro e `.crt`).
 *
 * Ordine obbligatorio: copia nel database -> rilettura -> verifica (chiave e certificato corrispondono,
 * snapshot identico) -> SOLO ALLORA si cancellano i file. Se un passo fallisce non si cancella nulla e
 * resta un avviso. Idempotente: si puo' rilanciare quante volte si vuole.
 */
class Migrator {

	const ISSUES = 'migration_issues';
	const GUARD  = "<?php exit; ?>\n";

	/** File di protezione che la vecchia cartella data/ si portava dietro. */
	private static $protection = array( '.htaccess', 'index.php', '.gitignore' );

	private static $ran    = false;
	private static $issues = array();

	/** Cartelle da cercare: [ data/ del plugin, uploads/wp-spid-cie-private ]. Filtrabile (test). */
	private static function dirs() {
		$legacy = '';
		if ( function_exists( 'wp_upload_dir' ) ) {
			$u      = wp_upload_dir();
			$legacy = empty( $u['basedir'] ) ? '' : trailingslashit( $u['basedir'] ) . 'wp-spid-cie-private/';
		}
		$dirs = array( 'data' => WPSPID_PLUGIN_DIR . 'data/', 'legacy' => $legacy );
		return (array) apply_filters( 'wpspid_migration_dirs', $dirs );
	}

	/** Una volta per richiesta, e solo se esiste ancora una vecchia cartella (due is_dir). */
	public static function maybe_run() {
		if ( self::$ran ) {
			return;
		}
		self::$ran = true;
		foreach ( self::dirs() as $dir ) {
			if ( $dir && is_dir( $dir ) ) {
				self::run();
				return;
			}
		}
	}

	/** Per i test: permette di rilanciare nella stessa richiesta. */
	public static function reset() {
		self::$ran    = false;
		self::$issues = array();
	}

	/** Avvisi lasciati dall'ultima migrazione incompleta. @return string[] */
	public static function issues() {
		$s = Storage::get( self::ISSUES );
		return $s ? array_values( array_map( 'strval', $s ) ) : array();
	}

	/**
	 * Esegue la migrazione.
	 *
	 * @return array {migrated:string[], issues:string[]}
	 */
	public static function run() {
		self::$ran    = true; // Evita la ricorsione: le verifiche leggono tramite CertificateManager.
		self::$issues = array();
		$migrated     = array();
		$dirs         = self::dirs();

		if ( ! empty( $dirs['data'] ) && is_dir( $dirs['data'] ) ) {
			$d = $dirs['data'];
			foreach ( (array) glob( $d . '*-sp.key.php' ) as $kf ) {
				$type = basename( $kf, '-sp.key.php' );
				if ( self::migrate_type( $type, $kf, $d . $type . '-sp.crt', true ) ) {
					$migrated[] = $type;
				}
			}
			foreach ( array( 'spid', 'cie' ) as $svc ) {
				if ( self::migrate_snapshot( $svc, $d ) ) {
					$migrated[] = 'registered-' . $svc;
				}
			}
			self::cleanup_dir( $d, true );
		}

		if ( ! empty( $dirs['legacy'] ) && is_dir( $dirs['legacy'] ) ) {
			$d = $dirs['legacy'];
			foreach ( (array) glob( $d . '*-sp.key' ) as $kf ) {
				$type = basename( $kf, '-sp.key' );
				if ( self::migrate_type( $type, $kf, $d . $type . '-sp.crt', false ) ) {
					$migrated[] = $type . ' (uploads)';
				}
			}
			self::cleanup_dir( $d, false );
		}

		if ( self::$issues ) {
			Storage::set( self::ISSUES, self::$issues );
		} else {
			Storage::delete( self::ISSUES );
		}
		return array( 'migrated' => $migrated, 'issues' => self::$issues );
	}

	private static function issue( $text ) {
		self::$issues[] = $text;
	}

	private static function read_key_file( $file, $guard ) {
		$c = @file_get_contents( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- il file puo' sparire: si gestisce il false.
		if ( false === $c ) {
			return false;
		}
		return $guard && 0 === strpos( $c, self::GUARD ) ? substr( $c, strlen( self::GUARD ) ) : $c;
	}

	/**
	 * Migra una coppia chiave/certificato.
	 *
	 * @param string $type
	 * @param string $key_file
	 * @param string $cert_file
	 * @param bool   $guard    La chiave ha il guard `<?php exit; ?>`.
	 * @return bool True se i dati sono nel database e verificati (i vecchi file sono stati cancellati).
	 */
	public static function migrate_type( $type, $key_file, $cert_file, $guard ) {
		if ( ! is_file( $key_file ) || ! is_file( $cert_file ) ) {
			self::issue( sprintf( 'Key or certificate file missing for "%s": nothing migrated, files left in place.', $type ) );
			return false;
		}
		$key  = self::read_key_file( $key_file, $guard );
		$cert = @file_get_contents( $cert_file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$pkey = $key ? openssl_pkey_get_private( $key ) : false;
		$x509 = $cert ? openssl_x509_read( $cert ) : false;
		if ( ! $pkey || ! $x509 || ! openssl_x509_check_private_key( $x509, $pkey ) ) {
			self::issue( sprintf( 'The old key/certificate pair "%s" is not valid or does not match: not migrated, files left in place.', $type ) );
			return false;
		}

		$existing = CertificateManager::record( $type );
		if ( $existing ) {
			// Gia' nel database: i file sono ridondanti solo se identici e leggibili.
			$open = KeyVault::open( $existing['key'] );
			if ( false !== $open['key'] && trim( $open['key'] ) === trim( $key ) && trim( $existing['cert'] ) === trim( $cert ) ) {
				self::delete_files( array( $key_file, $cert_file ) );
				return true;
			}
			self::issue( sprintf( 'The database already holds a different certificate for "%s": the old files were NOT deleted.', $type ) );
			return false;
		}

		try {
			CertificateManager::store( $type, $key, $cert ); // Scrive, rilegge e confronta; se non torna annulla.
		} catch ( \Throwable $e ) {
			self::issue( sprintf( 'Could not save "%s" in the database (%s): old files left in place.', $type, $e->getMessage() ) );
			return false;
		}

		// Seconda verifica, indipendente da store(): chiave e certificato riletti si corrispondono.
		$back_key  = CertificateManager::get_private_key( $type );
		$back_cert = CertificateManager::get_certificate( $type );
		$p2        = $back_key ? openssl_pkey_get_private( $back_key ) : false;
		$x2        = $back_cert ? openssl_x509_read( $back_cert ) : false;
		if ( ! $p2 || ! $x2 || ! openssl_x509_check_private_key( $x2, $p2 ) || trim( $back_key ) !== trim( $key ) ) {
			CertificateManager::delete( $type );
			self::issue( sprintf( 'Verification of "%s" after saving failed: rolled back, old files left in place.', $type ) );
			return false;
		}

		self::delete_files( array( $key_file, $cert_file ) );
		return true;
	}

	private static function migrate_snapshot( $svc, $dir ) {
		$xml_f  = $dir . 'registered-' . $svc . '.xml';
		$meta_f = $dir . 'registered-' . $svc . '.json';
		if ( ! is_file( $xml_f ) && ! is_file( $meta_f ) ) {
			return false;
		}
		$xml  = is_file( $xml_f ) ? (string) file_get_contents( $xml_f ) : '';
		$meta = is_file( $meta_f ) ? json_decode( (string) file_get_contents( $meta_f ), true ) : null;
		if ( '' === $xml || ! is_array( $meta ) || empty( $meta['sha256'] ) ) {
			self::issue( sprintf( 'The registered %s metadata files are incomplete: not migrated, files left in place.', strtoupper( $svc ) ) );
			return false;
		}
		$have = MetadataSnapshot::get( $svc );
		if ( $have ) {
			if ( $have['xml'] === $xml && $have['sha256'] === $meta['sha256'] ) {
				self::delete_files( array( $xml_f, $meta_f ) );
				return true;
			}
			self::issue( sprintf( 'The database already holds different registered %s metadata: old files were NOT deleted.', strtoupper( $svc ) ) );
			return false;
		}
		MetadataSnapshot::store_raw( $svc, $xml, $meta );
		$back = MetadataSnapshot::get( $svc );
		if ( ! $back || $back['xml'] !== $xml || $back['sha256'] !== $meta['sha256'] ) {
			MetadataSnapshot::delete( $svc );
			self::issue( sprintf( 'Verification of the registered %s metadata failed: rolled back, old files left in place.', strtoupper( $svc ) ) );
			return false;
		}
		self::delete_files( array( $xml_f, $meta_f ) );
		return true;
	}

	private static function delete_files( array $files ) {
		foreach ( $files as $f ) {
			if ( is_file( $f ) ) {
				wp_delete_file( $f );
			}
		}
	}

	/**
	 * Toglie la cartella se non contiene altro che i file di protezione della vecchia versione.
	 *
	 * @param string $dir
	 * @param bool   $has_protection data/ aveva .htaccess, index.php, .gitignore.
	 */
	private static function cleanup_dir( $dir, $has_protection ) {
		$left = array_diff( (array) scandir( $dir ), array( '.', '..' ) );
		$rest = $has_protection ? array_diff( $left, self::$protection ) : $left;
		if ( $rest ) {
			return; // Restano file che non abbiamo migrato: non si tocca niente.
		}
		self::delete_files( array_map( function ( $n ) use ( $dir ) { return $dir . $n; }, $left ) );
		@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- rimuove solo la vecchia cartella dati del plugin, ormai vuota
	}
}
