<?php
namespace WpSpidCie\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Cosa succede quando il plugin viene eliminato dalla schermata Plugin.
 *
 * - SEMPRE: si cancellano le cache e gli stati temporanei (sessioni dei cittadini, richieste in corso,
 *   anti-replay, elenco IdP, esito della verifica OpenSSL) e le opzioni di servizio.
 * - PER DEFAULT NON si cancellano il certificato, la chiave, il metadata registrato e le impostazioni
 *   dell'ente: rifare la registrazione presso AgID/CIE costa giorni e un'eliminazione per errore (o una
 *   reinstallazione) non deve farla perdere. Si cancellano solo con `WPSPID_REMOVE_DATA_ON_UNINSTALL`
 *   a true in wp-config.php.
 */
class Uninstaller {

	/** Opzioni di rete/sito con certificati e metadata registrato. */
	public static function network_options() {
		return array( 'wpspid_cert_spid', 'wpspid_cert_cie', 'wpspid_registered_spid', 'wpspid_registered_cie' );
	}

	public static function remove_data_requested() {
		return defined( 'WPSPID_REMOVE_DATA_ON_UNINSTALL' ) && true === (bool) WPSPID_REMOVE_DATA_ON_UNINSTALL;
	}

	public static function run() {
		$remove = self::remove_data_requested();

		$blogs = array( null );
		if ( function_exists( 'is_multisite' ) && is_multisite() && function_exists( 'get_sites' ) ) {
			$blogs = array_map( 'intval', (array) get_sites( array( 'fields' => 'ids', 'number' => 0 ) ) );
		}
		foreach ( $blogs as $blog_id ) {
			if ( null !== $blog_id ) {
				switch_to_blog( $blog_id );
			}
			self::clean_site( $remove );
			if ( null !== $blog_id ) {
				restore_current_blog();
			}
		}

		delete_site_option( 'wpspid_migration_issues' );
		if ( $remove ) {
			foreach ( self::network_options() as $name ) {
				delete_site_option( $name );
			}
		}
	}

	private static function clean_site( $remove ) {
		global $wpdb;
		delete_option( 'wpspid_production' );
		delete_option( 'wpspid_preserved_path' );
		delete_option( 'wpspid_restore_failed' );
		if ( $remove ) {
			delete_option( 'wpspid_options' );
		}
		// Transient e relativi timeout: sessioni, richieste in corso, anti-replay, cache IdP, probe.
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_wpspid\_%' OR option_name LIKE '\_transient\_timeout\_wpspid\_%'" ); // phpcs:ignore WordPress.DB
	}
}
