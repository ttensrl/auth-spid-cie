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
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'SPID/CIE blocked:', 'auth-spid-cie' ) . '</strong> ' . esc_html__( 'this server does not allow generating or using certificates.', 'auth-spid-cie' ) . '</p><ul style="list-style:disc;margin-left:20px"><li>' . implode( '</li><li>', array_map( 'esc_html', $probe['errors'] ) ) . '</li></ul><p>' . esc_html__( 'Login, ACS and metadata are disabled until the problem is solved.', 'auth-spid-cie' ) . ' <a href="' . esc_url( admin_url( 'options-general.php?page=wpspid-settings' ) ) . '">' . esc_html__( 'Check again', 'auth-spid-cie' ) . '</a>.</p></div>';
		}
		$failed = get_option( \WpSpidCie\Support\DataPreserver::FAILED );
		if ( $failed ) {
			echo '<div class="notice notice-error"><p>' . wp_kses(
				sprintf(
					/* translators: 1: path of the backup copy, 2: path where the data folder must be restored. */
					__( '<strong>SPID/CIE:</strong> after the update the data folder (keys and metadata) could not be put back in place. The backup copy is in %1$s: copy it to %2$s before doing anything else.', 'auth-spid-cie' ),
					'<code>' . esc_html( $failed ) . '</code>',
					'<code>' . esc_html( \WpSpidCie\Cert\CertificateManager::default_storage_dir() ) . '</code>'
				),
				array( 'strong' => array(), 'code' => array() )
			) . '</p></div>';
		}
	}

	public function on_init() {
		// Public actions here.
	}
}
