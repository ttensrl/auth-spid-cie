<?php
// phpcs:disable WordPress.Security.NonceVerification.Missing -- il nonce e' verificato con check_admin_referer() all'inizio di ogni handler (post_action).
namespace AuthSpidCie\Settings;

use AuthSpidCie\Cert\CertificateManager;
use AuthSpidCie\Cert\KeyVault;
use AuthSpidCie\Idp\CieMetadata;
use AuthSpidCie\Idp\Registry;
use AuthSpidCie\Idp\TestIdps;
use AuthSpidCie\Saml\MetadataBuilder;
use AuthSpidCie\Saml\MetadataSnapshot;
use AuthSpidCie\Support\Config;
use AuthSpidCie\Support\Requirements;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings → SPID/CIE. Collects everything the spid-cie-php setup asks for, manages the SP
 * certificates and shows what is still missing before the metadata can be registered.
 */
class AdminPage {

	const SLUG  = 'authspidcie-settings';
	const GROUP = 'authspidcie_options_group';
	const NONCE = 'authspidcie_admin';

	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_init', array( $this, 'register' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_post_authspidcie_cert_generate', array( $this, 'post_cert_generate' ) );
		add_action( 'admin_post_authspidcie_cert_import', array( $this, 'post_cert_import' ) );
		add_action( 'admin_post_authspidcie_cert_download', array( $this, 'post_cert_download' ) );
		add_action( 'admin_post_authspidcie_refresh', array( $this, 'post_refresh' ) );
		add_action( 'admin_post_authspidcie_probe', array( $this, 'post_probe' ) );
		add_action( 'admin_post_authspidcie_encrypt_key', array( $this, 'post_encrypt_key' ) );
		add_action( 'admin_post_authspidcie_meta_snapshot', array( $this, 'post_meta_snapshot' ) );
		add_action( 'admin_post_authspidcie_meta_download', array( $this, 'post_meta_download' ) );
	}

	public function add_menu() {
		add_options_page(
			__( 'SPID / CIE', 'auth-spid-cie' ),
			__( 'SPID / CIE', 'auth-spid-cie' ),
			'manage_options',
			self::SLUG,
			array( $this, 'render' )
		);
	}

	public function register() {
		register_setting( self::GROUP, OptionsManager::OPTION, array(
			'type'              => 'array',
			'sanitize_callback' => array( OptionsManager::class, 'sanitize' ),
			'default'           => OptionsManager::defaults(),
		) );
	}

	// ------------------------------------------------------------------ actions

	private function guard( $nonce_action ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'auth-spid-cie' ), 403 );
		}
		check_admin_referer( $nonce_action );
	}

	private function back( $type, $message ) {
		if ( 'success' === $type ) {
			$hint = $this->next_hint();
			if ( '' !== $hint ) {
				$message .= ' ' . $hint;
			}
		}
		set_transient( 'authspidcie_notice_' . get_current_user_id(), array( $type, $message ), 60 );
		wp_safe_redirect( admin_url( 'options-general.php?page=' . self::SLUG ) );
		exit;
	}

	private function service_from_post() {
		$service = isset( $_REQUEST['service'] ) ? sanitize_key( wp_unslash( $_REQUEST['service'] ) ) : 'spid'; // phpcs:ignore WordPress.Security.NonceVerification -- checked in guard().
		return 'cie' === $service ? 'cie' : 'spid';
	}

	public function post_cert_generate() {
		$this->guard( self::NONCE );
		$service = $this->service_from_post();

		$probe = Requirements::probe( true );
		if ( ! $probe['ok'] ) {
			$this->back( 'error', sprintf( /* translators: %s: list of problems found on the server. */ __( 'Generation blocked: %s', 'auth-spid-cie' ), implode( ' ', $probe['errors'] ) ) );
		}

		if ( CertificateManager::exists( $service ) && empty( $_POST['confirm_replace'] ) ) {
			$this->back( 'error', __( 'A certificate already exists: tick the confirmation to replace it (the metadata will have to be registered again).', 'auth-spid-cie' ) );
		}
		$c       = Config::options();
		$missing = array();
		foreach ( array( 'entity_id' => 'entityID', 'org_name' => __( 'Organization name', 'auth-spid-cie' ), 'org_display_name' => __( 'Display name', 'auth-spid-cie' ), 'org_code' => __( 'IPA code / VAT number / tax code', 'auth-spid-cie' ), 'locality' => __( 'Locality', 'auth-spid-cie' ) ) as $k => $label ) {
			if ( '' === trim( (string) $c[ $k ] ) ) {
				$missing[] = $label;
			}
		}
		if ( $missing ) {
			$this->back( 'error', sprintf( /* translators: %s: list of missing fields. */ __( 'Fill in and save these first: %s.', 'auth-spid-cie' ), implode( ', ', $missing ) ) );
		}

		try {
			CertificateManager::generate( $service, array(
				'org_name'       => $c['org_name'],
				'common_name'    => $c['org_display_name'],
				'uri'            => $c['entity_id'],
				'org_identifier' => Config::organization_identifier(),
				'country'        => $c['country'],
				'locality'       => $c['locality'],
				'public'         => Config::is_public(),
			), 730 );
		} catch ( \Exception $e ) {
			\AuthSpidCie\Support\Log::write( '[auth-spid-cie] cert generate: ' . $e->getMessage() );
			$this->back( 'error', sprintf( /* translators: %s: technical error message. */ __( 'Certificate generation failed: %s', 'auth-spid-cie' ), $e->getMessage() ) );
		}
		$this->back( 'success', sprintf( /* translators: %s: SPID or CIE. */ __( '%s certificate generated (valid for 730 days).', 'auth-spid-cie' ), strtoupper( $service ) ) );
	}

	public function post_cert_import() {
		$this->guard( self::NONCE );
		$service = $this->service_from_post();
		$errors  = Requirements::check();
		if ( $errors ) {
			$this->back( 'error', sprintf( /* translators: %s: list of problems found on the server. */ __( 'Import blocked: %s', 'auth-spid-cie' ), implode( ' ', $errors ) ) );
		}
		$key     = isset( $_POST['import_key'] ) ? trim( wp_unslash( $_POST['import_key'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- PEM, validated by OpenSSL.
		$cert    = isset( $_POST['import_cert'] ) ? trim( wp_unslash( $_POST['import_cert'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

		if ( CertificateManager::exists( $service ) && empty( $_POST['confirm_replace'] ) ) {
			$this->back( 'error', __( 'A certificate already exists: tick the confirmation to replace it.', 'auth-spid-cie' ) );
		}
		if ( '' === $key || '' === $cert ) {
			$this->back( 'error', __( 'Paste both the private key and the certificate (PEM format).', 'auth-spid-cie' ) );
		}
		try {
			CertificateManager::import( $service, $key, $cert );
		} catch ( \Exception $e ) {
			$this->back( 'error', sprintf( /* translators: %s: technical error message. */ __( 'Import failed: %s', 'auth-spid-cie' ), $e->getMessage() ) );
		}
		$this->back( 'success', sprintf( /* translators: %s: SPID or CIE. */ __( '%s certificate and key imported.', 'auth-spid-cie' ), strtoupper( $service ) ) );
	}

	public function post_cert_download() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'auth-spid-cie' ), 403 );
		}
		check_admin_referer( self::NONCE );
		$service = $this->service_from_post();
		$pem     = CertificateManager::get_certificate( $service );
		if ( ! $pem ) {
			wp_die( esc_html__( 'Certificate not found.', 'auth-spid-cie' ), 404 );
		}
		nocache_headers();
		header( 'Content-Type: application/x-x509-ca-cert' );
		header( 'Content-Disposition: attachment; filename="' . $service . '-sp.crt"' );
		echo $pem; // phpcs:ignore WordPress.Security.EscapeOutput -- PEM certificate.
		exit;
	}

	public function post_probe() {
		$this->guard( self::NONCE );
		$probe = Requirements::probe( true );
		$this->back( $probe['ok'] ? 'success' : 'error', $probe['ok'] ? __( 'Check passed: the server can generate and use certificates.', 'auth-spid-cie' ) : sprintf( /* translators: %s: list of problems found on the server. */ __( 'Check failed: %s', 'auth-spid-cie' ), implode( ' ', $probe['errors'] ) ) );
	}

	public function post_encrypt_key() {
		$this->guard( self::NONCE );
		$service = $this->service_from_post();
		try {
			CertificateManager::reseal( $service );
		} catch ( \Exception $e ) {
			$this->back( 'error', sprintf( /* translators: %s: technical error message. */ __( 'Not encrypted: %s', 'auth-spid-cie' ), $e->getMessage() ) );
		}
		$this->back( 'success', sprintf( /* translators: %s: SPID or CIE. */ __( 'The %s private key is now stored encrypted.', 'auth-spid-cie' ), strtoupper( $service ) ) );
	}

	public function post_meta_snapshot() {
		$this->guard( self::NONCE );
		$service = $this->service_from_post();
		$note    = isset( $_POST['note'] ) ? sanitize_text_field( wp_unslash( $_POST['note'] ) ) : '';
		try {
			MetadataSnapshot::save( $service, MetadataBuilder::generate( $service ), $note );
		} catch ( \Exception $e ) {
			$this->back( 'error', sprintf( /* translators: %s: technical error message. */ __( 'Not saved: %s', 'auth-spid-cie' ), $e->getMessage() ) );
		}
		$this->back( 'success', sprintf( /* translators: %s: SPID or CIE. */ __( '%s metadata saved as "registered".', 'auth-spid-cie' ), strtoupper( $service ) ) );
	}

	public function post_meta_download() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions.', 'auth-spid-cie' ), 403 );
		}
		check_admin_referer( self::NONCE );
		$service = $this->service_from_post();
		$which   = isset( $_GET['which'] ) && 'registered' === $_GET['which'] ? 'registered' : 'current'; // phpcs:ignore WordPress.Security.NonceVerification -- checked above.
		try {
			if ( 'registered' === $which ) {
				$saved = MetadataSnapshot::get( $service );
				if ( ! $saved ) {
					wp_die( esc_html__( 'No registered metadata has been saved.', 'auth-spid-cie' ), 404 );
				}
				$xml = $saved['xml'];
			} else {
				$xml = MetadataBuilder::generate( $service );
			}
		} catch ( \Exception $e ) {
			wp_die( esc_html( $e->getMessage() ), 500 );
		}
		nocache_headers();
		header( 'Content-Type: application/samlmetadata+xml; charset=UTF-8' );
		header( 'Content-Disposition: attachment; filename="metadata-' . $service . ( 'registered' === $which ? '-registered' : '' ) . '.xml"' );
		echo $xml; // phpcs:ignore WordPress.Security.EscapeOutput -- signed XML metadata.
		exit;
	}

	public function post_refresh() {
		$this->guard( self::NONCE );
		Registry::get_instance()->refresh();
		CieMetadata::refresh();
		TestIdps::refresh();
		$this->back( 'success', __( 'Identity Provider cache cleared: it will be reloaded on next use.', 'auth-spid-cie' ) );
	}

	// ------------------------------------------------------------------ helpers

	/** Values suggested from the site itself when a field is still empty. */
	private function suggestions() {
		$name = wp_strip_all_tags( get_bloginfo( 'name' ) );
		return array(
			'entity_id'        => home_url( '/' ),
			'org_url'          => home_url( '/' ),
			'org_name'         => $name,
			'org_display_name' => $name,
		);
	}

	private function req_mark() {
		return ' <span class="authspidcie-req" aria-hidden="true">*</span><span class="screen-reader-text"> ' . esc_html__( '(required)', 'auth-spid-cie' ) . '</span>';
	}

	private function badge( $tone, $label ) {
		$icons = array( 'ok' => 'yes-alt', 'bad' => 'dismiss', 'warn' => 'warning', 'off' => 'minus' );
		$icon  = isset( $icons[ $tone ] ) ? $icons[ $tone ] : 'marker';
		return '<span class="authspidcie-badge authspidcie-badge--' . esc_attr( $tone ) . '"><span class="dashicons dashicons-' . esc_attr( $icon ) . '" aria-hidden="true"></span> ' . esc_html( $label ) . '</span>';
	}

	/**
	 * Text row. Args: type, class, help, placeholder, required, prefilled (value suggested by the site),
	 * button (HTML placed after the field), label_public / label_private (label changes with the entity type).
	 */
	private function text_row( $label, $name, $value, $args = array() ) {
		$args = array_merge( array( 'type' => 'text', 'class' => 'regular-text', 'help' => '', 'placeholder' => '', 'required' => false, 'prefilled' => false, 'button' => '', 'label_attrs' => '', 'row_attrs' => '' ), $args );
		$id   = 'authspidcie_' . $name;
		echo '<tr' . $args['row_attrs'] . '><th scope="row"><label for="' . esc_attr( $id ) . '"' . $args['label_attrs'] . '><span class="authspidcie-label-text">' . esc_html( $label ) . '</span>' . ( $args['required'] ? $this->req_mark() : '' ) . '</label></th><td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- attrs are built internally with esc_attr().
		$class = $args['class'] . ( $args['prefilled'] ? ' authspidcie-suggested' : '' );
		printf(
			'<input type="%s" id="%s" name="%s[%s]" value="%s" class="%s" placeholder="%s"%s%s />',
			esc_attr( $args['type'] ),
			esc_attr( $id ),
			esc_attr( OptionsManager::OPTION ),
			esc_attr( $name ),
			esc_attr( $value ),
			esc_attr( $class ),
			esc_attr( $args['placeholder'] ),
			$args['required'] ? ' aria-required="true"' : '',
			false !== strpos( $args['class'], 'small-text' ) ? ' style="width:8em"' : '' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- constant strings.
		);
		if ( $args['button'] ) {
			echo ' ' . $args['button']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built internally.
		}
		if ( $args['help'] ) {
			echo '<p class="description">' . esc_html( $args['help'] ) . ( $args['prefilled'] ? ' <em>' . esc_html__( 'Suggested from your site: it becomes effective when you save.', 'auth-spid-cie' ) . '</em>' : '' ) . '</p>';
		} elseif ( $args['prefilled'] ) {
			echo '<p class="description"><em>' . esc_html__( 'Suggested from your site: it becomes effective when you save.', 'auth-spid-cie' ) . '</em></p>';
		}
		echo '</td></tr>';
	}

	private function check_row( $label, $name, $value, $help = '' ) {
		$id = 'authspidcie_' . $name;
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td><label for="' . esc_attr( $id ) . '"><input type="checkbox" id="' . esc_attr( $id ) . '" name="' . esc_attr( OptionsManager::OPTION ) . '[' . esc_attr( $name ) . ']" value="1" ' . checked( ! empty( $value ), true, false ) . ' /> ' . esc_html( $help ) . '</label></td></tr>';
	}

	private function select_row( $label, $name, $value, array $choices, $help = '', $row_attrs = '' ) {
		echo '<tr' . $row_attrs . '><th scope="row"><label for="authspidcie_' . esc_attr( $name ) . '">' . esc_html( $label ) . '</label></th><td><select id="authspidcie_' . esc_attr( $name ) . '" name="' . esc_attr( OptionsManager::OPTION ) . '[' . esc_attr( $name ) . ']">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $row_attrs is built internally.
		foreach ( $choices as $k => $text ) {
			echo '<option value="' . esc_attr( $k ) . '" ' . selected( (string) $value, (string) $k, false ) . '>' . esc_html( $text ) . '</option>';
		}
		echo '</select>';
		if ( $help ) {
			echo '<p class="description">' . esc_html( $help ) . '</p>';
		}
		echo '</td></tr>';
	}

	private function link( $url, $text ) {
		return '<a href="' . esc_url( $url ) . '" target="_blank" rel="noopener noreferrer">' . esc_html( $text ) . '</a>';
	}

	private function login_page_url() {
		return add_query_arg( 'authspidcie', 'choose', home_url( '/' ) );
	}

	private function metadata_url( $service ) {
		return add_query_arg( array( 'authspidcie' => 'metadata', 'service' => $service ), home_url( '/' ) );
	}

	/**
	 * Everything the screen needs to know about readiness, computed once.
	 *
	 * @return array {probe, services, infos, keys, snapshots, snapshot_status, list {steps, next}}
	 */
	private function collect_state( array $c ) {
		$probe    = Requirements::probe();
		$services = $infos = $keys = $snapshots = $snap_full = array();
		foreach ( array( 'spid', 'cie' ) as $s ) {
			$enabled = ! empty( $c[ $s . '_enabled' ] );
			$missing = $enabled ? OptionsManager::missing_for_metadata( $c, $s ) : array();
			$info    = CertificateManager::info( $s );
			$key     = $info ? CertificateManager::key_state( $s ) : null;

			$infos[ $s ]    = $info;
			$keys[ $s ]     = $key;
			$services[ $s ] = Readiness::service( $s, array(
				'enabled'  => $enabled,
				'probe_ok' => ! empty( $probe['ok'] ),
				'missing'  => $missing,
				'has_cert' => (bool) $info,
				'key_ok'   => $key ? KeyVault::is_readable_status( $key['status'] ) : false,
			) );
			$snapshots[ $s ] = 'none';
			if ( Readiness::READY === $services[ $s ]['state'] ) {
				try {
					$snap_full[ $s ] = MetadataSnapshot::status( $s, MetadataBuilder::generate( $s ) );
					$snapshots[ $s ] = $snap_full[ $s ]['state'];
				} catch ( \Exception $e ) {
					$snap_full[ $s ] = null;
				}
			}
		}
		return array(
			'probe'           => $probe,
			'services'        => $services,
			'infos'           => $infos,
			'keys'            => $keys,
			'snapshots'       => $snapshots,
			'snapshot_status' => $snap_full,
			'list'            => Readiness::checklist( $c, $services, $snapshots ),
		);
	}

	/** "Next step: …" sentence appended to the success notices. */
	private function next_hint() {
		try {
			$state = $this->collect_state( Config::options() );
		} catch ( \Exception $e ) {
			return '';
		}
		$next = $state['list']['next'];
		if ( ! $next ) {
			return __( 'Everything is set up.', 'auth-spid-cie' );
		}
		return sprintf( /* translators: %s: title of the next step of the checklist. */ __( 'Next step: %s.', 'auth-spid-cie' ), $next['title'] );
	}

	public function enqueue_assets( $hook ) {
		if ( 'settings_page_' . self::SLUG !== $hook ) {
			return;
		}
		wp_enqueue_style( 'authspidcie-admin', AUTHSPIDCIE_PLUGIN_URL . 'assets/css/admin.css', array( 'dashicons' ), AUTHSPIDCIE_VERSION );
		wp_enqueue_script( 'authspidcie-admin', AUTHSPIDCIE_PLUGIN_URL . 'assets/js/admin.js', array(), AUTHSPIDCIE_VERSION, true );
	}

	// ------------------------------------------------------------------ rendering

	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$c     = Config::options();
		$state = $this->collect_state( $c );

		echo '<div class="wrap authspidcie-admin"><h1>' . esc_html__( 'SPID / CIE', 'auth-spid-cie' ) . '</h1>';
		$this->render_notices( $state );
		$this->render_site_box();
		$this->render_checklist( $state );

		echo '<nav class="authspidcie-nav" aria-label="' . esc_attr__( 'Sections of this page', 'auth-spid-cie' ) . '"><ul>';
		foreach ( array(
			'authspidcie-stato'       => __( 'Status', 'auth-spid-cie' ),
			'authspidcie-ente'        => __( 'Organization', 'auth-spid-cie' ),
			'authspidcie-prove'       => __( 'Tests', 'auth-spid-cie' ),
			'authspidcie-avanzate'    => __( 'Advanced', 'auth-spid-cie' ),
			'authspidcie-certificati' => __( 'Certificates', 'auth-spid-cie' ),
		) as $anchor => $label ) {
			echo '<li><a href="#' . esc_attr( $anchor ) . '">' . esc_html( $label ) . '</a></li>';
		}
		echo '</ul></nav>';

		$this->render_status( $c, $state );
		$this->render_form( $c, $state );
		$this->render_certificates( $state );

		echo '</div>';
	}

	/** Result of the last action, outcome of the settings form, and validation errors. */
	private function render_notices( array $state ) {
		$notice = get_transient( 'authspidcie_notice_' . get_current_user_id() );
		if ( $notice ) {
			delete_transient( 'authspidcie_notice_' . get_current_user_id() );
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', 'success' === $notice[0] ? 'success' : 'error', esc_html( $notice[1] ) );
		}

		$updated = isset( $_GET['settings-updated'] ) && 'true' === $_GET['settings-updated']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only flag set by options.php.
		if ( ! $updated ) {
			return;
		}
		$errors = get_settings_errors( OptionsManager::OPTION );
		if ( $errors ) {
			settings_errors( OptionsManager::OPTION );
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'The fields reported above were not saved and kept their previous value. Every other change was saved.', 'auth-spid-cie' ) . '</p></div>';
			return;
		}
		$text = __( 'Settings saved.', 'auth-spid-cie' );
		$warn = array();
		foreach ( $state['snapshots'] as $service => $st ) {
			if ( 'changed' === $st ) {
				$warn[] = strtoupper( $service );
			}
		}
		if ( $warn ) {
			printf(
				'<div class="notice notice-success is-dismissible"><p>%s</p></div><div class="notice notice-warning"><p><strong>%s</strong> %s</p></div>',
				esc_html( $text ),
				esc_html( sprintf( /* translators: %s: SPID and/or CIE. */ __( 'The %s metadata changed.', 'auth-spid-cie' ), implode( ' / ', $warn ) ) ),
				esc_html__( 'It is no longer the copy you saved as registered. If the change is intended, download the new metadata and register it again; otherwise restore the previous values.', 'auth-spid-cie' )
			);
			return;
		}
		$next = $state['list']['next'];
		printf(
			'<div class="notice notice-success is-dismissible"><p>%s %s</p></div>',
			esc_html( $text ),
			$next ? esc_html( sprintf( /* translators: %s: title of the next step of the checklist. */ __( 'Next step: %s.', 'auth-spid-cie' ), $next['title'] ) ) : esc_html__( 'Everything is set up.', 'auth-spid-cie' )
		);
	}

	/** Which site is being configured and the other sites of the network. */
	private function render_site_box() {
		echo '<div class="authspidcie-card authspidcie-site"><p><span class="dashicons dashicons-admin-site-alt3" aria-hidden="true"></span> <strong>' . esc_html__( 'You are configuring this site:', 'auth-spid-cie' ) . '</strong> <code>' . esc_html( home_url( '/' ) ) . '</code></p>';
		echo '<p class="description">' . esc_html__( 'These settings belong to this site only; the certificate and key are shared by the whole network.', 'auth-spid-cie' ) . '</p>';
		if ( is_multisite() && current_user_can( 'manage_network' ) ) {
			$links = array();
			foreach ( get_sites( array( 'number' => 50, 'fields' => 'ids' ) ) as $id ) {
				if ( (int) $id === get_current_blog_id() ) {
					continue;
				}
				$links[] = '<a href="' . esc_url( get_admin_url( $id, 'options-general.php?page=authspidcie-settings' ) ) . '">' . esc_html( get_home_url( $id, '/' ) ) . '</a>';
			}
			if ( $links ) {
				echo '<p class="description">' . esc_html__( 'Other sites of the network:', 'auth-spid-cie' ) . ' ' . implode( ' &middot; ', $links ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- each link is built with esc_url()/esc_html().
			}
		}
		echo '</div>';
	}

	private function render_checklist( array $state ) {
		$list  = $state['list'];
		$extra = array(
			'register' => array(
				array( 'https://demo.spid.gov.it', __( 'SPID Demo (tests)', 'auth-spid-cie' ) ),
				array( 'https://validator.spid.gov.it', __( 'AgID Validator', 'auth-spid-cie' ) ),
				array( 'https://developers.italia.it/it/cie', __( 'CIE: how to join', 'auth-spid-cie' ) ),
			),
		);
		echo '<div class="authspidcie-card authspidcie-steps-card"><h2>' . esc_html__( 'To activate SPID/CIE', 'auth-spid-cie' ) . '</h2>';
		if ( $list['next'] ) {
			echo '<p class="authspidcie-next"><strong>' . esc_html( sprintf( /* translators: 1: step number, 2: total steps. */ __( 'Next step (%1$d of %2$d):', 'auth-spid-cie' ), $list['next']['number'], count( $list['steps'] ) ) ) . '</strong> ' . esc_html( $list['next']['title'] ) . ' &mdash; <a href="#' . esc_attr( $list['next']['anchor'] ) . '">' . esc_html__( 'go to the section', 'auth-spid-cie' ) . '</a></p>';
		} else {
			echo '<p class="authspidcie-next authspidcie-next--done"><strong>' . esc_html__( 'Everything is set up.', 'auth-spid-cie' ) . '</strong></p>';
		}
		echo '<ol class="authspidcie-steps">';
		$icons = array( 'done' => 'yes-alt', 'warn' => 'warning', 'todo' => 'marker' );
		foreach ( $list['steps'] as $step ) {
			echo '<li class="authspidcie-step authspidcie-step--' . esc_attr( $step['status'] ) . '"><span class="dashicons dashicons-' . esc_attr( $icons[ $step['status'] ] ) . '" aria-hidden="true"></span><div><strong>' . esc_html( $step['title'] ) . '</strong>';
			echo '<span class="screen-reader-text"> &mdash; ' . esc_html( 'done' === $step['status'] ? __( 'done', 'auth-spid-cie' ) : ( 'warn' === $step['status'] ? __( 'needs attention', 'auth-spid-cie' ) : __( 'to do', 'auth-spid-cie' ) ) ) . '</span>';
			echo '<p>' . esc_html( $step['text'] ) . '</p>';
			if ( 'register' === $step['id'] && 'done' !== $step['status'] ) {
				$links = array();
				foreach ( $extra['register'] as $l ) {
					$links[] = $this->link( $l[0], $l[1] );
				}
				echo '<p class="authspidcie-links">' . implode( ' &middot; ', $links ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built with esc_url()/esc_html().
			}
			if ( 'login' === $step['id'] ) {
				echo '<p class="authspidcie-links"><a href="' . esc_url( $this->login_page_url() ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Open the login page of this site', 'auth-spid-cie' ) . '</a></p>';
			}
			echo '</div></li>';
		}
		echo '</ol></div>';
	}

	/** Traffic light per service, plus the secondary details. */
	private function render_status( array $c, array $state ) {
		echo '<section id="authspidcie-stato" class="authspidcie-section"><h2>' . esc_html__( 'Status', 'auth-spid-cie' ) . '</h2><div class="authspidcie-grid">';
		foreach ( array( 'spid' => 'SPID', 'cie' => 'CIE' ) as $service => $label ) {
			$this->render_service_card( $service, $label, $state );
		}
		echo '</div>';
		$this->render_technical( $c, $state );
		echo '</section>';
	}

	private function render_service_card( $service, $label, array $state ) {
		$info = $state['services'][ $service ];
		$cert = $state['infos'][ $service ];
		$key  = $state['keys'][ $service ];
		echo '<div class="authspidcie-card authspidcie-service authspidcie-service--' . esc_attr( $info['tone'] ) . '"><h3>' . esc_html( $label ) . ' ' . $this->badge( $info['tone'], $info['label'] ) . '</h3>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- badge() escapes.
		echo '<p>' . esc_html( $info['text'] ) . '</p>';
		if ( Readiness::MISSING_DATA === $info['state'] ) {
			echo '<p><a class="button" href="#authspidcie-ente">' . esc_html__( 'Fill in the organization data', 'auth-spid-cie' ) . '</a></p>';
		} elseif ( Readiness::NO_CERT === $info['state'] ) {
			echo '<p><a class="button button-primary" href="#authspidcie-certificati">' . esc_html__( 'Go to Certificates', 'auth-spid-cie' ) . '</a></p>';
		}
		if ( $cert && Readiness::OFF !== $info['state'] ) {
			$ok = $cert['days_left'] > 30;
			echo '<p class="' . ( $ok ? 'authspidcie-ok' : 'authspidcie-bad' ) . '"><span class="dashicons dashicons-' . ( $ok ? 'yes' : 'warning' ) . '" aria-hidden="true"></span> ' . esc_html(
				sprintf(
					/* translators: 1: number of days, 2: expiry date. */
					_n( 'Certificate valid for %1$d more day (expires on %2$s)', 'Certificate valid for %1$d more days (expires on %2$s)', (int) $cert['days_left'], 'auth-spid-cie' ),
					(int) $cert['days_left'],
					wp_date( get_option( 'date_format' ), $cert['valid_to'] )
				)
			) . '</p>';
		}
		if ( $cert && $key && Readiness::OFF !== $info['state'] ) {
			$this->render_key_state( $service, $key );
		}
		if ( Readiness::READY === $info['state'] ) {
			$url = $this->metadata_url( $service );
			echo '<p class="authspidcie-meta"><strong>' . esc_html__( 'Metadata address', 'auth-spid-cie' ) . '</strong><br /><code>' . esc_html( $url ) . '</code></p>';
			echo '<p><a class="button button-primary" href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=authspidcie_meta_download&service=' . $service . '&which=current' ), self::NONCE ) ) . '"><span class="dashicons dashicons-download" aria-hidden="true"></span> ' . esc_html__( 'Download the metadata', 'auth-spid-cie' ) . '</a> '
				. '<a class="button" href="' . esc_url( $url ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Open in the browser', 'auth-spid-cie' ) . '</a> '
				. '<button type="button" class="button authspidcie-copy" data-copy="' . esc_attr( $url ) . '" data-done="' . esc_attr__( 'Copied', 'auth-spid-cie' ) . '">' . esc_html__( 'Copy the address', 'auth-spid-cie' ) . '</button></p>';
			$this->render_snapshot( $service, $state['snapshot_status'][ $service ] );
		}
		echo '</div>';
	}

	private function render_key_state( $service, array $key ) {
		$st = $key['status'];
		if ( KeyVault::S_OK === $st ) {
			echo '<p class="authspidcie-ok"><span class="dashicons dashicons-lock" aria-hidden="true"></span> ' . esc_html__( 'Private key stored encrypted (AUTHSPIDCIE_SECRET).', 'auth-spid-cie' ) . '</p>';
		} elseif ( KeyVault::S_PLAIN === $st ) {
			echo '<p class="authspidcie-warn"><span class="dashicons dashicons-warning" aria-hidden="true"></span> ' . esc_html__( 'Private key stored in the database WITHOUT encryption: database backups contain it. To encrypt it, define AUTHSPIDCIE_SECRET in wp-config.php (see the documentation).', 'auth-spid-cie' ) . '</p>';
		} elseif ( KeyVault::S_PLAIN_PENDING === $st ) {
			echo '<p class="authspidcie-warn"><span class="dashicons dashicons-warning" aria-hidden="true"></span> ' . esc_html__( 'AUTHSPIDCIE_SECRET is defined but the private key is still stored without encryption.', 'auth-spid-cie' ) . '</p>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="authspidcie_encrypt_key" /><input type="hidden" name="service" value="' . esc_attr( $service ) . '" />';
			wp_nonce_field( self::NONCE );
			submit_button( __( 'Encrypt now', 'auth-spid-cie' ), 'secondary small', 'submit', false );
			echo '</form>';
		} else {
			echo '<p class="authspidcie-bad"><span class="dashicons dashicons-dismiss" aria-hidden="true"></span> ' . esc_html( KeyVault::message( $st ) ) . '</p>';
		}
	}

	/** Optional copy of the metadata handed to AgID/CIE, with a plain explanation. */
	private function render_snapshot( $service, $status ) {
		if ( ! is_array( $status ) ) {
			return;
		}
		$dl    = function ( $which ) use ( $service ) {
			return wp_nonce_url( admin_url( 'admin-post.php?action=authspidcie_meta_download&service=' . $service . '&which=' . $which ), self::NONCE );
		};
		$state = $status['state'];
		echo '<details class="authspidcie-more"' . ( 'changed' === $state ? ' open' : '' ) . '><summary>' . esc_html__( 'Already registered? Keep a copy (optional)', 'auth-spid-cie' ) . '</summary>';
		echo '<p class="description">' . esc_html__( 'When you register the metadata with AgID/CIE, save a copy here. If you later change something that alters the metadata, the plugin will tell you that the registration must be repeated.', 'auth-spid-cie' ) . '</p>';
		if ( 'none' === $state ) {
			echo '<p>' . esc_html__( 'No copy saved yet.', 'auth-spid-cie' ) . '</p>';
		} else {
			$date = wp_date( get_option( 'date_format' ), strtotime( $status['saved_at'] ) );
			if ( 'same' === $state ) {
				/* translators: %s: date the copy was saved. */
				echo '<p class="authspidcie-ok"><span class="dashicons dashicons-yes" aria-hidden="true"></span> ' . esc_html( sprintf( __( 'The metadata is identical to the copy saved on %s.', 'auth-spid-cie' ), $date ) ) . '</p>';
			} else {
				/* translators: %s: date the copy was saved. */
				echo '<p class="authspidcie-bad"><span class="dashicons dashicons-warning" aria-hidden="true"></span> ' . esc_html( sprintf( __( 'The metadata is different from the copy saved on %s. If the change is intended, repeat the registration with AgID/CIE and then save a new copy.', 'auth-spid-cie' ), $date ) ) . '</p>';
			}
			if ( ! empty( $status['note'] ) ) {
				echo '<p>' . esc_html( $status['note'] ) . '</p>';
			}
			echo '<p><a class="button" href="' . esc_url( $dl( 'registered' ) ) . '">' . esc_html__( 'Download saved copy', 'auth-spid-cie' ) . '</a></p>';
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="authspidcie-inline"><input type="hidden" name="action" value="authspidcie_meta_snapshot" /><input type="hidden" name="service" value="' . esc_attr( $service ) . '" />';
		wp_nonce_field( self::NONCE );
		echo '<label class="screen-reader-text" for="authspidcie_note_' . esc_attr( $service ) . '">' . esc_html__( 'Note', 'auth-spid-cie' ) . '</label><input type="text" id="authspidcie_note_' . esc_attr( $service ) . '" name="note" placeholder="' . esc_attr__( 'Note (e.g. registered on ...)', 'auth-spid-cie' ) . '" class="regular-text" /> ';
		submit_button( __( 'Save the current metadata as the registered copy', 'auth-spid-cie' ), 'secondary', 'submit', false );
		echo '</form></details>';
	}

	/** Secondary information: server, endpoints, environment, where data lives. */
	private function render_technical( array $c, array $state ) {
		$probe = $state['probe'];
		echo '<details class="authspidcie-card authspidcie-tech"><summary>' . esc_html__( 'Technical details', 'auth-spid-cie' ) . '</summary><table class="widefat striped" role="presentation"><tbody>';
		echo '<tr><th scope="row">' . esc_html__( 'Server', 'auth-spid-cie' ) . '</th><td>';
		if ( $probe['ok'] ) {
			echo '<span class="authspidcie-ok"><span class="dashicons dashicons-yes" aria-hidden="true"></span> ' . esc_html__( 'OpenSSL is working', 'auth-spid-cie' ) . '</span> (' . esc_html( $probe['openssl_version'] ) . ')';
		} else {
			echo '<span class="authspidcie-bad"><span class="dashicons dashicons-dismiss" aria-hidden="true"></span> ' . esc_html__( 'The server does not allow using certificates: SPID/CIE is blocked.', 'auth-spid-cie' ) . '</span><ul class="authspidcie-list">';
			foreach ( $probe['errors'] as $err ) {
				echo '<li>' . esc_html( $err ) . '</li>';
			}
			echo '</ul>';
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="authspidcie-inline"><input type="hidden" name="action" value="authspidcie_probe" />';
		wp_nonce_field( self::NONCE );
		submit_button( __( 'Check again', 'auth-spid-cie' ), 'link', 'submit', false );
		echo '</form></td></tr>';
		echo '<tr><th scope="row">' . esc_html__( 'Environment', 'auth-spid-cie' ) . '</th><td>' . ( Config::is_production() ? '<strong class="authspidcie-bad">' . esc_html__( 'PRODUCTION', 'auth-spid-cie' ) . '</strong>' : esc_html__( 'Test (test IdPs are visible)', 'auth-spid-cie' ) ) . '</td></tr>';
		echo '<tr><th scope="row">' . esc_html__( 'Addresses', 'auth-spid-cie' ) . '</th><td>ACS: <code>' . esc_html( Config::acs_url() ) . '</code><br />' . esc_html__( 'Logout:', 'auth-spid-cie' ) . ' <code>' . esc_html( Config::slo_url() ) . '</code></td></tr>';
		echo '<tr><th scope="row">' . esc_html__( 'Data', 'auth-spid-cie' ) . '</th><td>' . wp_kses(
			__( 'Keys, certificates and registered metadata are stored in the <strong>WordPress database</strong> (not in files), so updating or reinstalling the plugin does not lose them. They are kept when the plugin is deleted unless <code>AUTHSPIDCIE_REMOVE_DATA_ON_UNINSTALL</code> is set. Database backups contain the private key: to store it encrypted, define <code>AUTHSPIDCIE_SECRET</code> in wp-config.php.', 'auth-spid-cie' ),
			array( 'code' => array(), 'strong' => array() )
		) . '</td></tr>';
		echo '<tr><th scope="row">' . esc_html__( 'Identity providers', 'auth-spid-cie' ) . '</th><td><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="authspidcie-inline"><input type="hidden" name="action" value="authspidcie_refresh" />';
		wp_nonce_field( self::NONCE );
		submit_button( __( 'Refresh Identity Provider list', 'auth-spid-cie' ), 'secondary small', 'submit', false );
		echo '</form></td></tr>';
		echo '</tbody></table></details>';
	}

	/** One form for everything the Settings API saves (checkbox semantics rely on that). */
	private function render_form( array $c, array $state ) {
		$name    = OptionsManager::OPTION;
		$private = 'private' === $c['sp_type'];
		$sug     = $this->suggestions();
		$val     = function ( $key ) use ( $c, $sug ) {
			$stored = isset( $c[ $key ] ) ? (string) $c[ $key ] : '';
			return array( '' !== trim( $stored ) ? $stored : ( isset( $sug[ $key ] ) ? $sug[ $key ] : '' ), '' === trim( $stored ) && isset( $sug[ $key ] ) && '' !== $sug[ $key ] );
		};
		$cie_missing  = Readiness::MISSING_DATA === $state['services']['cie']['state'];
		$bill_missing = $private && Readiness::MISSING_DATA === $state['services']['spid']['state'];

		echo '<form action="options.php" method="post" id="authspidcie-main-form">';
		settings_fields( self::GROUP );
		echo '<input type="hidden" name="' . esc_attr( $name ) . '[_form]" value="1" />';

		// --- Organization -------------------------------------------------
		echo '<section id="authspidcie-ente" class="authspidcie-section"><h2>' . esc_html__( 'Organization', 'auth-spid-cie' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'Fields marked * are needed to produce valid metadata.', 'auth-spid-cie' ) . '</p>';

		echo '<div class="authspidcie-card"><h3>' . esc_html__( 'Login', 'auth-spid-cie' ) . '</h3><table class="form-table" role="presentation">';
		$this->check_row( __( 'Enable login', 'auth-spid-cie' ), 'enabled', $c['enabled'], __( 'Turn on the login pages. The metadata stays reachable even when this is off.', 'auth-spid-cie' ) );
		$this->check_row( 'SPID', 'spid_enabled', $c['spid_enabled'], __( 'Enable login with SPID', 'auth-spid-cie' ) );
		$this->check_row( 'CIE', 'cie_enabled', $c['cie_enabled'], __( 'Enable login with the Electronic Identity Card (CIE)', 'auth-spid-cie' ) );
		echo '</table></div>';

		echo '<div class="authspidcie-card"><h3>' . esc_html__( 'Who you are', 'auth-spid-cie' ) . '</h3><table class="form-table" role="presentation">';
		$this->select_row( __( 'Entity type', 'auth-spid-cie' ), 'sp_type', $c['sp_type'], array( 'public' => __( 'Public Administration', 'auth-spid-cie' ), 'private' => __( 'Private entity', 'auth-spid-cie' ) ), __( 'Public administrations are identified by the IPA code; private entities by VAT number or tax code and need some extra data.', 'auth-spid-cie' ) );
		list( $v, $pre ) = $val( 'org_name' );
		$this->text_row( __( 'Organization name', 'auth-spid-cie' ), 'org_name', $v, array( 'required' => true, 'prefilled' => $pre, 'help' => __( 'Full legal name, e.g. "Comune di Roma". Used in the metadata and in the certificate.', 'auth-spid-cie' ) ) );
		list( $v, $pre ) = $val( 'org_display_name' );
		$this->text_row( __( 'Display name', 'auth-spid-cie' ), 'org_display_name', $v, array( 'required' => true, 'prefilled' => $pre, 'help' => __( 'The short name citizens will see at the identity provider, e.g. "Comune di Roma".', 'auth-spid-cie' ) ) );
		list( $v, $pre ) = $val( 'org_url' );
		$this->text_row( __( 'Organization website', 'auth-spid-cie' ), 'org_url', $v, array( 'required' => true, 'class' => 'large-text', 'type' => 'url', 'prefilled' => $pre, 'placeholder' => 'https://www.example.it', 'help' => __( 'The address of your institutional website.', 'auth-spid-cie' ) ) );
		$this->select_row( __( 'Code type', 'auth-spid-cie' ), 'org_code_type', $c['org_code_type'], array( 'VATNumber' => __( 'VAT number', 'auth-spid-cie' ), 'FiscalCode' => __( 'Tax code', 'auth-spid-cie' ) ), __( 'Private entities only.', 'auth-spid-cie' ), ' data-authspidcie-when="private"' );
		$this->text_row(
			$private ? __( 'VAT number / Tax code', 'auth-spid-cie' ) : __( 'IPA code', 'auth-spid-cie' ),
			'org_code',
			$c['org_code'],
			array(
				'required'    => true,
				'label_attrs' => ' data-label-public="' . esc_attr__( 'IPA code', 'auth-spid-cie' ) . '" data-label-private="' . esc_attr__( 'VAT number / Tax code', 'auth-spid-cie' ) . '"',
				'placeholder' => $private ? '01234567890' : 'c_h501',
				'help'        => __( 'Public administration: the IPA code, e.g. c_h501 (you find it on indicepa.gov.it). Private entity: the VAT number without the IT prefix, or the tax code.', 'auth-spid-cie' ),
			)
		);
		$this->text_row( __( 'Locality', 'auth-spid-cie' ), 'locality', $c['locality'], array( 'required' => true, 'help' => __( 'The town where the organization is based, e.g. Roma. Written in the certificate.', 'auth-spid-cie' ) ) );
		$this->text_row( __( 'Contact email', 'auth-spid-cie' ), 'contact_email', $c['contact_email'], array( 'required' => true, 'type' => 'email', 'placeholder' => 'servizi.digitali@example.it', 'help' => __( 'Technical contact for AgID and the identity providers.', 'auth-spid-cie' ) ) );
		$this->text_row( __( 'Contact phone', 'auth-spid-cie' ), 'contact_phone', $c['contact_phone'], array( 'required' => true, 'placeholder' => '+39 06 12345678' ) );
		echo '</table></div>';

		echo '<div class="authspidcie-card"><h3>' . esc_html__( 'Site identifier (entityID)', 'auth-spid-cie' ) . '</h3><table class="form-table" role="presentation">';
		list( $v, $pre ) = $val( 'entity_id' );
		$this->text_row(
			'entityID',
			'entity_id',
			$v,
			array(
				'required'    => true,
				'class'       => 'large-text',
				'prefilled'   => $pre,
				'placeholder' => home_url( '/' ),
				'button'      => '<button type="button" class="button authspidcie-use-site" data-target="authspidcie_entity_id" data-value="' . esc_attr( home_url( '/' ) ) . '">' . esc_html__( 'Use the address of this site', 'auth-spid-cie' ) . '</button>',
				'help'        => __( 'The address that identifies your site towards SPID/CIE. Use the address of this site, without parameters. Once registered with AgID it must not change.', 'auth-spid-cie' ),
			)
		);
		echo '</table></div>';

		// Data only some entities need: opened by themselves when something is missing.
		echo '<details class="authspidcie-card authspidcie-more" data-authspidcie-when="cie"' . ( $cie_missing ? ' open' : '' ) . '><summary>' . esc_html__( 'Extra data for CIE', 'auth-spid-cie' ) . '</summary><table class="form-table" role="presentation">';
		if ( $private ) {
			$this->text_row( __( 'Tax code', 'auth-spid-cie' ), 'cie_fiscal_code', $c['cie_fiscal_code'], array( 'help' => __( 'Required for private entities.', 'auth-spid-cie' ) ) );
			$this->text_row( __( 'ATECO / NACE2 code', 'auth-spid-cie' ), 'cie_nace2', $c['cie_nace2'], array( 'class' => 'small-text', 'help' => __( 'Required for private entities (e.g. 84.11).', 'auth-spid-cie' ) ) );
		}
		$this->text_row( __( 'Municipality ISTAT code', 'auth-spid-cie' ), 'cie_municipality', $c['cie_municipality'], array( 'class' => 'small-text', 'required' => true, 'help' => __( 'The 6-digit ISTAT code of your municipality, e.g. 058091 for Rome.', 'auth-spid-cie' ) ) );
		$this->text_row( __( 'Province code', 'auth-spid-cie' ), 'cie_province', $c['cie_province'], array( 'class' => 'small-text', 'required' => true, 'help' => __( 'The two-letter province code, e.g. RM.', 'auth-spid-cie' ) ) );
		echo '</table></details>';

		echo '<details class="authspidcie-card authspidcie-more" data-authspidcie-when="private"' . ( $bill_missing ? ' open' : '' ) . '><summary>' . esc_html__( 'Billing data (private entities only)', 'auth-spid-cie' ) . '</summary>';
		echo '<p class="description">' . wp_kses( __( 'SPID Notice no. 29 v.3: <code>CessionarioCommittente</code> in the metadata of private entities.', 'auth-spid-cie' ), array( 'code' => array() ) ) . '</p><table class="form-table" role="presentation">';
		$this->text_row( 'IdPaese', 'fpa_id_paese', $c['fpa_id_paese'], array( 'class' => 'small-text' ) );
		$this->text_row( 'IdCodice', 'fpa_id_codice', $c['fpa_id_codice'] );
		$this->text_row( __( 'Business name', 'auth-spid-cie' ), 'fpa_denominazione', $c['fpa_denominazione'] );
		$this->text_row( __( 'Address', 'auth-spid-cie' ), 'fpa_indirizzo', $c['fpa_indirizzo'] );
		$this->text_row( __( 'Street number', 'auth-spid-cie' ), 'fpa_numero_civico', $c['fpa_numero_civico'], array( 'class' => 'small-text' ) );
		$this->text_row( 'CAP', 'fpa_cap', $c['fpa_cap'], array( 'class' => 'small-text' ) );
		$this->text_row( __( 'Municipality', 'auth-spid-cie' ), 'fpa_comune', $c['fpa_comune'] );
		$this->text_row( __( 'Province', 'auth-spid-cie' ), 'fpa_provincia', $c['fpa_provincia'], array( 'class' => 'small-text' ) );
		$this->text_row( __( 'Country', 'auth-spid-cie' ), 'fpa_nazione', $c['fpa_nazione'], array( 'class' => 'small-text' ) );
		$this->text_row( __( 'Legal name (contact)', 'auth-spid-cie' ), 'fpa_org_name', $c['fpa_org_name'] );
		$this->text_row( __( 'Email (contact)', 'auth-spid-cie' ), 'fpa_email', $c['fpa_email'], array( 'type' => 'email' ) );
		$this->text_row( __( 'Phone (contact)', 'auth-spid-cie' ), 'fpa_phone', $c['fpa_phone'] );
		echo '</table></details>';

		echo '<div class="authspidcie-card"><h3>' . esc_html__( 'Data requested from the citizen', 'auth-spid-cie' ) . '</h3><p class="description">' . esc_html__( 'All selected attributes must be returned by the IdP, otherwise the login is rejected. The tax code is always required. CIE only returns tax code, first name, last name and date of birth.', 'auth-spid-cie' ) . '</p><div class="authspidcie-attrs">';
		foreach ( OptionsManager::attributes_catalog() as $attr => $def ) {
			$fixed = 'fiscalNumber' === $attr;
			printf(
				'<label><input type="checkbox" name="%s[attributes][]" value="%s" %s %s /> %s <code>%s</code></label>',
				esc_attr( $name ),
				esc_attr( $attr ),
				checked( in_array( $attr, (array) $c['attributes'], true ), true, false ),
				$fixed ? 'disabled checked' : '',
				esc_html( $def[0] ),
				esc_html( $attr )
			);
		}
		echo '<input type="hidden" name="' . esc_attr( $name ) . '[attributes][]" value="fiscalNumber" /></div></div>';
		submit_button( __( 'Save settings', 'auth-spid-cie' ), 'primary', 'submit', true, array( 'id' => 'authspidcie-save-1' ) );
		echo '</section>';

		// --- Tests ---------------------------------------------------------
		echo '<section id="authspidcie-prove" class="authspidcie-section"><h2>' . esc_html__( 'Tests', 'auth-spid-cie' ) . '</h2><div class="authspidcie-card">';
		echo '<p>' . esc_html__( 'Before going live, try the login with the SPID Demo environment. Save first, then open the login page of this site and choose "SPID Demo".', 'auth-spid-cie' ) . ' <a class="button" href="' . esc_url( $this->login_page_url() ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Open the login page', 'auth-spid-cie' ) . '</a></p>';
		echo '<table class="form-table" role="presentation">';
		$this->check_row( __( 'SPID Demo', 'auth-spid-cie' ), 'test_demo', $c['test_demo'], __( 'Show the SPID Demo identity provider (demo.spid.gov.it) in the login page. Only when not in production.', 'auth-spid-cie' ) );
		$this->check_row( __( 'SPID Demo (Validator mode)', 'auth-spid-cie' ), 'test_demo_validator', $c['test_demo_validator'], __( 'The same environment, with the checks of the Validator on the login requests (demo.spid.gov.it/validator).', 'auth-spid-cie' ) );
		$this->check_row( __( 'AgID Validator', 'auth-spid-cie' ), 'test_validator', $c['test_validator'], __( 'The official AgID validator (validator.spid.gov.it).', 'auth-spid-cie' ) );
		$this->check_row( __( 'Production environment', 'auth-spid-cie' ), 'production', $c['production'], __( 'Hides every test provider. Tick it only when AgID (SPID) and the Ministry (CIE) have accepted your registration.', 'auth-spid-cie' ) );
		echo '</table></div>';
		submit_button( __( 'Save settings', 'auth-spid-cie' ), 'primary', 'submit', true, array( 'id' => 'authspidcie-save-2' ) );
		echo '</section>';

		// --- Advanced ------------------------------------------------------
		echo '<section id="authspidcie-avanzate" class="authspidcie-section"><details class="authspidcie-card authspidcie-advanced"><summary><strong>' . esc_html__( 'Advanced options', 'auth-spid-cie' ) . '</strong> &mdash; ' . esc_html__( 'the defaults are fine for most sites', 'auth-spid-cie' ) . '</summary><table class="form-table" role="presentation">';
		$this->text_row( __( 'Service name', 'auth-spid-cie' ), 'sp_name', $c['sp_name'], array( 'help' => __( 'Shown in the metadata (AttributeConsumingService). If empty, the display name is used.', 'auth-spid-cie' ) ) );
		$this->text_row( __( 'Service description', 'auth-spid-cie' ), 'sp_description', $c['sp_description'], array( 'class' => 'large-text' ) );
		$this->text_row( __( 'Country (ISO 3166-1)', 'auth-spid-cie' ), 'country', $c['country'], array( 'class' => 'small-text' ) );
		$this->select_row( __( 'CIE level', 'auth-spid-cie' ), 'cie_level', $c['cie_level'], array( 1 => __( 'Level 1', 'auth-spid-cie' ), 2 => __( 'Level 2 (recommended)', 'auth-spid-cie' ), 3 => __( 'Level 3', 'auth-spid-cie' ) ), __( 'Assurance level requested for CIE. SPID uses level 2 unless the login link specifies otherwise.', 'auth-spid-cie' ) );
		$this->select_row( __( 'Request Destination', 'auth-spid-cie' ), 'destination_mode', $c['destination_mode'], array( 'sso_url' => __( 'SSO service URL (recommended)', 'auth-spid-cie' ), 'entity_id' => __( 'IdP entityID (like spid-php)', 'auth-spid-cie' ) ), __( 'Change only if an identity provider requires it.', 'auth-spid-cie' ) );
		$this->text_row( 'AttributeConsumingServiceIndex', 'acs_index', $c['acs_index'], array( 'type' => 'number', 'class' => 'small-text', 'help' => __( 'Index of the attribute set in the metadata (normally 0).', 'auth-spid-cie' ) ) );
		echo '<tr><th scope="row"><label for="authspidcie_test_idp_urls">' . esc_html__( 'Custom test IdPs', 'auth-spid-cie' ) . '</label></th><td><textarea id="authspidcie_test_idp_urls" name="' . esc_attr( $name ) . '[test_idp_urls]" rows="3" class="large-text code" placeholder="https://localhost:8443/metadata.xml">' . esc_textarea( implode( "\n", (array) $c['test_idp_urls'] ) ) . '</textarea><p class="description">' . esc_html__( 'One metadata URL (https) per line, max 5. Example: a local spid-saml-check.', 'auth-spid-cie' ) . '</p></td></tr>';
		echo '<tr><th scope="row"><label for="authspidcie_test_idp_xml">' . esc_html__( 'Test IdP metadata (XML)', 'auth-spid-cie' ) . '</label></th><td><textarea id="authspidcie_test_idp_xml" name="' . esc_attr( $name ) . '[test_idp_xml]" rows="4" class="large-text code" placeholder="&lt;EntityDescriptor ...&gt;">' . esc_textarea( (string) $c['test_idp_xml'] ) . '</textarea><p class="description">' . esc_html__( 'Alternative to the URL: paste here the XML metadata of a test IdP (spid-saml-check, spid-sp-test).', 'auth-spid-cie' ) . '</p></td></tr>';
		$this->check_row( __( 'Unverified TLS (testing only)', 'auth-spid-cie' ), 'test_insecure_tls', $c['test_insecure_tls'], __( 'Accepts self-signed certificates from local test IdPs. Never in production.', 'auth-spid-cie' ) );
		echo '</table></details>';
		submit_button( __( 'Save settings', 'auth-spid-cie' ), 'primary', 'submit', true, array( 'id' => 'authspidcie-save-3' ) );
		echo '</section></form>';
	}

	private function render_certificates( array $state ) {
		echo '<section id="authspidcie-certificati" class="authspidcie-section"><h2>' . esc_html__( 'Certificates', 'auth-spid-cie' ) . '</h2><p class="description">' . wp_kses( __( 'The certificate signs requests and metadata. If you have already registered an SP with AgID/CIE, <strong>import</strong> the existing key and certificate instead of generating new ones, otherwise you will have to repeat the registration. The private key is never shown.', 'auth-spid-cie' ), array( 'strong' => array() ) ) . '</p>';
		$probe = $state['probe'];
		if ( ! $probe['ok'] ) {
			echo '<div class="notice notice-error inline"><p><strong>' . esc_html__( 'Certificate generation and import are not available:', 'auth-spid-cie' ) . '</strong> ' . esc_html( implode( ' ', $probe['errors'] ) ) . '</p></div></section>';
			return;
		}
		echo '<div class="authspidcie-grid">';
		foreach ( array( 'spid' => 'SPID', 'cie' => 'CIE' ) as $service => $label ) {
			$info = $state['infos'][ $service ];
			echo '<div class="authspidcie-card"><h3>' . esc_html( $label ) . ' ' . ( $info ? $this->badge( 'ok', __( 'Present', 'auth-spid-cie' ) ) : $this->badge( 'bad', __( 'Missing', 'auth-spid-cie' ) ) ) . '</h3>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- badge() escapes.
			if ( $info ) {
				echo '<p>' . esc_html__( 'Subject:', 'auth-spid-cie' ) . ' <code>' . esc_html( $info['subject'] ) . '</code><br />' . esc_html__( 'Identifier:', 'auth-spid-cie' ) . ' <code>' . esc_html( $info['organization_identifier'] ) . '</code><br />SHA-256: <code class="authspidcie-wrap">' . esc_html( $info['fingerprint'] ) . '</code></p>';
				$dl = wp_nonce_url( admin_url( 'admin-post.php?action=authspidcie_cert_download&service=' . $service ), self::NONCE );
				echo '<p><a class="button" href="' . esc_url( $dl ) . '">' . esc_html__( 'Download certificate (.crt)', 'auth-spid-cie' ) . '</a></p>';
			} else {
				echo '<p>' . esc_html__( 'Save the organization data first, then generate the certificate here.', 'auth-spid-cie' ) . '</p>';
			}
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="authspidcie-confirm-form"><input type="hidden" name="action" value="authspidcie_cert_generate" /><input type="hidden" name="service" value="' . esc_attr( $service ) . '" />';
			wp_nonce_field( self::NONCE );
			if ( $info ) {
				echo '<p><label><input type="checkbox" name="confirm_replace" value="1" class="authspidcie-confirm" /> ' . esc_html__( 'I confirm: replace the existing certificate', 'auth-spid-cie' ) . '</label></p>';
			}
			submit_button( $info ? __( 'Regenerate', 'auth-spid-cie' ) : __( 'Generate certificate', 'auth-spid-cie' ), $info ? 'secondary' : 'primary', 'submit', false );
			echo '</form>';
			echo '<details class="authspidcie-more"><summary>' . esc_html__( 'Import existing key and certificate', 'auth-spid-cie' ) . '</summary>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="authspidcie-confirm-form"><input type="hidden" name="action" value="authspidcie_cert_import" /><input type="hidden" name="service" value="' . esc_attr( $service ) . '" />';
			wp_nonce_field( self::NONCE );
			echo '<p><label for="authspidcie_import_key_' . esc_attr( $service ) . '">' . esc_html__( 'Private key (PEM)', 'auth-spid-cie' ) . '</label><br /><textarea id="authspidcie_import_key_' . esc_attr( $service ) . '" name="import_key" rows="5" class="large-text code" autocomplete="off" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></p>';
			echo '<p><label for="authspidcie_import_cert_' . esc_attr( $service ) . '">' . esc_html__( 'Certificate (PEM)', 'auth-spid-cie' ) . '</label><br /><textarea id="authspidcie_import_cert_' . esc_attr( $service ) . '" name="import_cert" rows="5" class="large-text code" placeholder="-----BEGIN CERTIFICATE-----"></textarea></p>';
			if ( $info ) {
				echo '<p><label><input type="checkbox" name="confirm_replace" value="1" class="authspidcie-confirm" /> ' . esc_html__( 'I confirm: replace the existing certificate', 'auth-spid-cie' ) . '</label></p>';
			}
			submit_button( __( 'Import', 'auth-spid-cie' ), 'secondary', 'submit', false );
			echo '</form></details></div>';
		}
		echo '</div></section>';
	}
}
