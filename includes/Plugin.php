<?php
namespace AuthSpidCie;

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
		// Chiavi, certificati e metadata registrati stanno nel database. Le versioni precedenti li
		// tenevano in file (data/): se ne restano, li si sposta qui (con verifica prima di cancellare).
		\AuthSpidCie\Cert\Migrator::maybe_run();
		add_action( 'admin_notices', array( $this, 'admin_notices' ) );

		// Initialize settings (sempre: serve a vedere perche' il plugin e' bloccato).
		\AuthSpidCie\Settings\AdminPage::get_instance();

		// Se la verifica pratica di OpenSSL e' fallita il login e i metadata restano spenti.
		$probe = \AuthSpidCie\Support\Requirements::cached();
		if ( $probe && empty( $probe['ok'] ) ) {
			return;
		}

		// Initialize router.
		\AuthSpidCie\Http\Router::get_instance();

		// Pulsanti ([spid_button], [cie_button], [authspidcie_login]) e integrazione con il tema.
		\AuthSpidCie\Ui\Shortcodes::register();
		\AuthSpidCie\Integrations\Theme::register();

		// Add hooks.
		add_action( 'init', array( $this, 'on_init' ) );
	}

	public function admin_notices() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$probe = \AuthSpidCie\Support\Requirements::cached();
		if ( $probe && empty( $probe['ok'] ) ) {
			echo '<div class="notice notice-error"><p><strong>' . esc_html__( 'SPID/CIE blocked:', 'auth-spid-cie' ) . '</strong> ' . esc_html__( 'this server does not allow generating or using certificates.', 'auth-spid-cie' ) . '</p><ul style="list-style:disc;margin-left:20px"><li>' . implode( '</li><li>', array_map( 'esc_html', $probe['errors'] ) ) . '</li></ul><p>' . esc_html__( 'Login, ACS and metadata are disabled until the problem is solved.', 'auth-spid-cie' ) . ' <a href="' . esc_url( admin_url( 'options-general.php?page=authspidcie-settings' ) ) . '">' . esc_html__( 'Check again', 'auth-spid-cie' ) . '</a>.</p></div>';
		}
		foreach ( array( 'spid' => 'SPID', 'cie' => 'CIE' ) as $service => $label ) {
			$state = \AuthSpidCie\Cert\CertificateManager::key_state( $service );
			if ( \AuthSpidCie\Cert\KeyVault::S_MISSING === $state['status'] || $state['readable'] ) {
				continue;
			}
			echo '<div class="notice notice-error"><p><strong>' . esc_html( sprintf( /* translators: %s: SPID or CIE. */ __( 'SPID/CIE (%s): the private key is unusable.', 'auth-spid-cie' ), $label ) ) . '</strong> ' . esc_html( \AuthSpidCie\Cert\KeyVault::message( $state['status'] ) ) . ' ' . esc_html__( 'Login and metadata for this service are disabled.', 'auth-spid-cie' ) . '</p></div>';
		}
		$issues = \AuthSpidCie\Cert\Migrator::issues();
		if ( $issues ) {
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'SPID/CIE: the move of the old key files to the database is not complete.', 'auth-spid-cie' ) . '</strong> ' . esc_html__( 'Nothing was deleted: the old files are still where they were.', 'auth-spid-cie' ) . '</p><ul style="list-style:disc;margin-left:20px"><li>' . implode( '</li><li>', array_map( 'esc_html', $issues ) ) . '</li></ul></div>';
		}
	}

	public function on_init() {
		// Public actions here.
	}
}
