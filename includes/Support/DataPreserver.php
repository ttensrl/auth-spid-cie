<?php
namespace WpSpidCie\Support;

use WpSpidCie\Cert\CertificateManager;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Mette al riparo la cartella dati (chiavi, certificati, metadata registrati) durante
 * l'aggiornamento del plugin.
 *
 * WordPress aggiorna un plugin cancellando l'intera cartella precedente (clear_destination) e
 * copiando quella nuova: tutto cio' che sta in `data/` andrebbe perso, e il certificato registrato
 * presso AgID/CIE con lui. Prima dell'aggiornamento (`upgrader_pre_install`) si copia `data/` in
 * `wp-content/upgrade/`; dopo (`upgrader_post_install`) la si rimette nella cartella nuova,
 * verificando che i file siano identici. Se la copia di sicurezza non riesce, l'aggiornamento viene
 * annullato; se il ripristino non riesce, la copia resta sul disco e compare un avviso con il percorso.
 *
 * Non copre: eliminazione del plugin, reupload via FTP, deploy con `rsync --delete`, aggiornamenti
 * interrotti. In quei casi si perde la cartella: vedi docs/STORAGE.md.
 */
class DataPreserver {

	const OPTION = 'wpspid_preserved_path';
	const FAILED = 'wpspid_restore_failed';

	/** Solo per i test: cartella dati e cartella delle copie di sicurezza alternative. */
	public static $test_dir         = null;
	public static $test_backup_root = null;
	public static $test_folder      = null;

	/** Dimentica lo stato della richiesta (processi lunghi come WP-CLI e test). */
	public static function reset_state() {
		self::$protected = false;
	}

	/** Una sola copia di sicurezza per richiesta (negli aggiornamenti scattano due filtri). */
	private static $protected = false;

	public static function register() {
		// Aggiornamento di un plugin gia' installato: hook_extra ha la chiave 'plugin'.
		add_filter( 'upgrader_pre_install', array( __CLASS__, 'on_pre_install' ), 10, 2 );
		// Reinstallazione / upload con "sostituisci quello attuale" / wp plugin install --force:
		// hook_extra NON ha 'plugin', ma la cartella scompattata si chiama auth-spid-cie.
		// Scatta prima della cancellazione della cartella esistente.
		add_filter( 'upgrader_source_selection', array( __CLASS__, 'on_source_selection' ), 10, 4 );
		add_filter( 'upgrader_post_install', array( __CLASS__, 'on_post_install' ), 10, 3 );
		// Installazione fallita: se la cartella dati e' ancora al suo posto la copia non serve piu'.
		add_filter( 'upgrader_install_package_result', array( __CLASS__, 'on_install_result' ), 10, 2 );
	}

	private static function plugin_folder() {
		return null !== self::$test_folder ? self::$test_folder : basename( rtrim( WPSPID_PLUGIN_DIR, '/' ) );
	}

	private static function is_this_plugin( $hook_extra ) {
		if ( ! is_array( $hook_extra ) || empty( $hook_extra['plugin'] ) ) {
			return false;
		}
		return self::plugin_folder() . '/auth-spid-cie.php' === $hook_extra['plugin'];
	}

	/** Cartella dati da proteggere, o null se sta fuori dal plugin (WPSPID_PRIVATE_DIR). */
	private static function data_dir() {
		if ( null !== self::$test_dir ) {
			return self::$test_dir;
		}
		if ( defined( 'WPSPID_PRIVATE_DIR' ) && WPSPID_PRIVATE_DIR ) {
			return null;
		}
		return rtrim( CertificateManager::default_storage_dir(), '/' );
	}

	private static function backup_root() {
		return null !== self::$test_backup_root ? self::$test_backup_root : rtrim( WP_CONTENT_DIR, '/' ) . '/upgrade';
	}

	/**
	 * Copia di sicurezza della cartella dati.
	 *
	 * @return true|\WP_Error True anche se non c'e' nulla da proteggere; WP_Error se la copia fallisce.
	 */
	private static function protect() {
		$src = self::data_dir();
		if ( self::$protected || null === $src || ! is_dir( $src ) ) {
			return true;
		}
		$backup = self::backup_root() . '/wpspid-preserve-' . bin2hex( random_bytes( 6 ) );
		if ( ! self::backup( $src, $backup ) ) {
			return new \WP_Error( 'wpspid_backup_failed', __( 'Operation cancelled: the keys and metadata of the SPID/CIE plugin (data/ folder) could not be safely backed up. Check the permissions of wp-content/upgrade.', 'auth-spid-cie' ) );
		}
		update_option( self::OPTION, $backup, false );
		self::$protected = true;
		return true;
	}

	/**
	 * @param bool|\WP_Error $response   Esito dei passi precedenti.
	 * @param array          $hook_extra Contesto dell'aggiornamento.
	 * @return bool|\WP_Error
	 */
	public static function on_pre_install( $response, $hook_extra ) {
		if ( ! self::is_this_plugin( $hook_extra ) ) {
			return $response;
		}
		$r = self::protect();
		return true === $r ? $response : $r;
	}

	/**
	 * @param string $source        Cartella scompattata del pacchetto.
	 * @param string $remote_source Cartella di lavoro.
	 * @param mixed  $upgrader      WP_Upgrader.
	 * @param array  $hook_extra    Contesto.
	 * @return string|\WP_Error
	 */
	public static function on_source_selection( $source, $remote_source, $upgrader, $hook_extra ) {
		if ( ! is_array( $hook_extra ) || ( $hook_extra['type'] ?? '' ) !== 'plugin' || ! is_string( $source ) ) {
			return $source;
		}
		$folder = basename( rtrim( $source, '/' ) );
		if ( self::plugin_folder() !== $folder || ! is_file( rtrim( $source, '/' ) . '/auth-spid-cie.php' ) ) {
			return $source;
		}
		$r = self::protect();
		return true === $r ? $source : $r;
	}

	/**
	 * @param bool|\WP_Error $response
	 * @param array          $hook_extra
	 * @param array          $result     Contiene 'destination': cartella del plugin appena installato.
	 * @return bool|\WP_Error
	 */
	public static function on_post_install( $response, $hook_extra, $result ) {
		$backup = get_option( self::OPTION );
		if ( ! $backup || ! is_dir( $backup ) || empty( $result['destination'] ) ) {
			return $response;
		}
		// Il segnale e' la copia di sicurezza fatta prima: riguarda solo la cartella del nostro plugin.
		if ( basename( rtrim( $result['destination'], '/' ) ) !== self::plugin_folder() && ! self::is_this_plugin( $hook_extra ) && null === self::$test_dir ) {
			return $response;
		}
		$dest = rtrim( $result['destination'], '/' ) . '/data';
		self::$protected = false;
		if ( self::restore( $backup, $dest ) ) {
			delete_option( self::OPTION );
		} else {
			update_option( self::FAILED, $backup, false );
		}
		return $response;
	}

	/**
	 * Dopo l'installazione del pacchetto. Se e' fallita e la cartella dati esiste ancora ed e' identica
	 * alla copia, la copia di sicurezza e' inutile e viene tolta (non resta una copia della chiave
	 * dimenticata in wp-content/upgrade). Se la cartella e' stata gia' cancellata la copia resta.
	 *
	 * @param array|\WP_Error $result
	 * @param array           $hook_extra
	 * @return array|\WP_Error Invariato.
	 */
	public static function on_install_result( $result, $hook_extra ) {
		if ( ! is_wp_error( $result ) ) {
			return $result;
		}
		$backup = get_option( self::OPTION );
		$data   = self::data_dir();
		if ( $backup && is_dir( $backup ) && null !== $data && is_dir( $data ) && self::identical( $backup, $data ) ) {
			self::remove_dir( $backup );
			delete_option( self::OPTION );
			self::$protected = false;
		}
		return $result;
	}

	/**
	 * Copia $src in $backup. False se non c'e' nulla da copiare o la copia non e' identica.
	 */
	public static function backup( $src, $backup ) {
		if ( ! is_dir( $src ) ) {
			return false;
		}
		if ( ! self::copy_dir( $src, $backup ) || ! self::identical( $src, $backup ) ) {
			self::remove_dir( $backup );
			return false;
		}
		return true;
	}

	/**
	 * Rimette $backup in $dest e, solo se la verifica riesce, elimina la copia di sicurezza.
	 * Se fallisce lascia la copia dov'e'.
	 */
	public static function restore( $backup, $dest ) {
		if ( ! is_dir( $backup ) ) {
			return false;
		}
		if ( ! @self::copy_dir( $backup, $dest ) || ! self::identical( $backup, $dest ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return false;
		}
		self::remove_dir( $backup );
		return true;
	}

	/** Copia ricorsiva (file nascosti inclusi) mantenendo i permessi. */
	private static function copy_dir( $src, $dst ) {
		if ( ! is_dir( $dst ) && ! @mkdir( $dst, fileperms( $src ) & 0777, true ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- copia durante l'aggiornamento, mantiene i permessi
			return false;
		}
		foreach ( scandir( $src ) as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			$from = $src . '/' . $name;
			$to   = $dst . '/' . $name;
			if ( is_dir( $from ) ) {
				if ( ! self::copy_dir( $from, $to ) ) {
					return false;
				}
				continue;
			}
			if ( ! @copy( $from, $to ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return false;
			}
			chmod( $to, fileperms( $from ) & 0777 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- permessi restrittivi sulla chiave privata: WP_Filesystem non e' adatto
		}
		return true;
	}

	/** Stessi file, stessa dimensione e stesso contenuto (hash). */
	private static function identical( $a, $b ) {
		foreach ( scandir( $a ) as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			$fa = $a . '/' . $name;
			$fb = $b . '/' . $name;
			if ( is_dir( $fa ) ) {
				if ( ! is_dir( $fb ) || ! self::identical( $fa, $fb ) ) {
					return false;
				}
			} elseif ( ! is_file( $fb ) || md5_file( $fa ) !== md5_file( $fb ) ) {
				return false;
			}
		}
		return true;
	}

	public static function remove_dir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		foreach ( scandir( $dir ) as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			$p = $dir . '/' . $name;
			is_dir( $p ) && ! is_link( $p ) ? self::remove_dir( $p ) : wp_delete_file( $p );
		}
		@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- pulizia della copia temporanea
	}
}
