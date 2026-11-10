<?php
namespace WpSpidCie;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Main Plugin Class (Singleton).
 */
class Plugin {
	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		$this->init();
	}

	private function init() {
		// I dati (chiavi, certificati, metadata registrati) stanno in data/: l'aggiornamento del
		// plugin cancella la cartella, quindi vanno messi al riparo e rimessi dopo.
		\WpSpidCie\Support\DataPreserver::register();
		add_action( 'admin_notices', array( $this, 'admin_notices' ) );

		// Initialize settings (sempre: serve a vedere perche' il plugin e' bloccato).
		\WpSpidCie\Settings\AdminPage::get_instance();

		// Se la verifica pratica di OpenSSL e' fallita il login e i metadata restano spenti.
		$probe = \WpSpidCie\Support\Requirements::cached();
		if ( $probe && empty( $probe['ok'] ) ) {
			return;
		}

		// Initialize router.
		\WpSpidCie\Http\Router::get_instance();

		// Pulsanti ([spid_button], [cie_button], [wpspid_login]) e integrazione con il tema.
		\WpSpidCie\Ui\Shortcodes::register();
		\WpSpidCie\Integrations\Theme::register();

		// Add hooks.
		add_action( 'init', array( $this, 'on_init' ) );
	}

	public function admin_notices() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$probe = \WpSpidCie\Support\Requirements::cached();
		if ( $probe && empty( $probe['ok'] ) ) {
			echo '<div class="notice notice-error"><p><strong>SPID/CIE bloccato:</strong> questo server non permette di generare o usare i certificati.</p><ul style="list-style:disc;margin-left:20px"><li>' . implode( '</li><li>', array_map( 'esc_html', $probe['errors'] ) ) . '</li></ul><p>Login, ACS e metadata sono disattivati finché il problema non è risolto. <a href="' . esc_url( admin_url( 'options-general.php?page=wpspid-settings' ) ) . '">Ricontrolla</a>.</p></div>';
		}
		$failed = get_option( \WpSpidCie\Support\DataPreserver::FAILED );
		if ( $failed ) {
			echo '<div class="notice notice-error"><p><strong>SPID/CIE:</strong> dopo l\'aggiornamento non è stato possibile rimettere al suo posto la cartella dei dati (chiavi e metadata). La copia di sicurezza è in <code>' . esc_html( $failed ) . '</code>: copiala in <code>' . esc_html( \WpSpidCie\Cert\CertificateManager::default_storage_dir() ) . '</code> prima di fare altro.</p></div>';
		}
	}

	public function on_init() {
		// Public actions here.
	}
}
