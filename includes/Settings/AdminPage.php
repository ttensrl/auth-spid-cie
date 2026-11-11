<?php
// phpcs:disable WordPress.Security.NonceVerification.Missing -- il nonce e' verificato con check_admin_referer() all'inizio di ogni handler (post_action).
namespace WpSpidCie\Settings;

use WpSpidCie\Cert\CertificateManager;
use WpSpidCie\Cert\KeyVault;
use WpSpidCie\Idp\CieMetadata;
use WpSpidCie\Idp\Registry;
use WpSpidCie\Idp\TestIdps;
use WpSpidCie\Saml\MetadataBuilder;
use WpSpidCie\Saml\MetadataSnapshot;
use WpSpidCie\Support\Config;
use WpSpidCie\Support\Requirements;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings → SPID/CIE. Collects everything the spid-cie-php setup asks for, manages the SP
 * certificates and shows what is still missing before the metadata can be registered.
 */
class AdminPage {

	const SLUG  = 'wpspid-settings';
	const GROUP = 'wpspid_options_group';
	const NONCE = 'wpspid_admin';

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
		add_action( 'admin_post_wpspid_cert_generate', array( $this, 'post_cert_generate' ) );
		add_action( 'admin_post_wpspid_cert_import', array( $this, 'post_cert_import' ) );
		add_action( 'admin_post_wpspid_cert_download', array( $this, 'post_cert_download' ) );
		add_action( 'admin_post_wpspid_refresh', array( $this, 'post_refresh' ) );
		add_action( 'admin_post_wpspid_probe', array( $this, 'post_probe' ) );
		add_action( 'admin_post_wpspid_encrypt_key', array( $this, 'post_encrypt_key' ) );
		add_action( 'admin_post_wpspid_meta_snapshot', array( $this, 'post_meta_snapshot' ) );
		add_action( 'admin_post_wpspid_meta_download', array( $this, 'post_meta_download' ) );
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
		set_transient( 'wpspid_notice_' . get_current_user_id(), array( $type, $message ), 60 );
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
			\WpSpidCie\Support\Log::write( '[auth-spid-cie] cert generate: ' . $e->getMessage() );
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

	// ------------------------------------------------------------------ rendering

	private function text_row( $label, $name, $value, $args = array() ) {
		$args = array_merge( array( 'type' => 'text', 'class' => 'regular-text', 'help' => '', 'placeholder' => '', 'required' => false ), $args );
		echo '<tr><th scope="row"><label for="wpspid_' . esc_attr( $name ) . '">' . esc_html( $label ) . ( $args['required'] ? ' <span style="color:#b32d2e">*</span>' : '' ) . '</label></th><td>';
		// .small-text di WordPress e' largo 50px: tronca CAP (5 cifre) e codice ISTAT (6 cifre).
		$style = false !== strpos( $args['class'], 'small-text' ) ? ' style="width:8em"' : '';
		printf(
			'<input type="%s" id="wpspid_%s" name="%s[%s]" value="%s" class="%s" placeholder="%s"' . $style . ' />', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $style e' una costante interna
			esc_attr( $args['type'] ),
			esc_attr( $name ),
			esc_attr( OptionsManager::OPTION ),
			esc_attr( $name ),
			esc_attr( $value ),
			esc_attr( $args['class'] ),
			esc_attr( $args['placeholder'] )
		);
		if ( $args['help'] ) {
			echo '<p class="description">' . esc_html( $args['help'] ) . '</p>';
		}
		echo '</td></tr>';
	}

	private function check_row( $label, $name, $value, $help = '' ) {
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td><label><input type="checkbox" name="' . esc_attr( OptionsManager::OPTION ) . '[' . esc_attr( $name ) . ']" value="1" ' . checked( ! empty( $value ), true, false ) . ' /> ' . esc_html( $help ) . '</label></td></tr>';
	}

	private function select_row( $label, $name, $value, array $choices, $help = '' ) {
		echo '<tr><th scope="row"><label for="wpspid_' . esc_attr( $name ) . '">' . esc_html( $label ) . '</label></th><td><select id="wpspid_' . esc_attr( $name ) . '" name="' . esc_attr( OptionsManager::OPTION ) . '[' . esc_attr( $name ) . ']">';
		foreach ( $choices as $k => $text ) {
			echo '<option value="' . esc_attr( $k ) . '" ' . selected( (string) $value, (string) $k, false ) . '>' . esc_html( $text ) . '</option>';
		}
		echo '</select>';
		if ( $help ) {
			echo '<p class="description">' . esc_html( $help ) . '</p>';
		}
		echo '</td></tr>';
	}

	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$c      = Config::options();
		$name   = OptionsManager::OPTION;
		$notice = get_transient( 'wpspid_notice_' . get_current_user_id() );
		if ( $notice ) {
			delete_transient( 'wpspid_notice_' . get_current_user_id() );
		}
		$private = 'private' === $c['sp_type'];

		echo '<div class="wrap"><h1>' . esc_html__( 'SPID / CIE', 'auth-spid-cie' ) . '</h1>';
		if ( $notice ) {
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', 'success' === $notice[0] ? 'success' : 'error', esc_html( $notice[1] ) );
		}
		settings_errors( OptionsManager::OPTION );

		$this->render_status( $c );

		echo '<form action="options.php" method="post">';
		settings_fields( self::GROUP );
		echo '<input type="hidden" name="' . esc_attr( $name ) . '[_form]" value="1" />';

		// --- Generale ---
		echo '<h2>' . esc_html__( '1. General', 'auth-spid-cie' ) . '</h2><table class="form-table" role="presentation">';
		$this->check_row( __( 'Enable login', 'auth-spid-cie' ), 'enabled', $c['enabled'], __( 'Enable the login/ACS routes (the metadata always remains reachable)', 'auth-spid-cie' ) );
		$this->check_row( __( 'Production environment', 'auth-spid-cie' ), 'production', $c['production'], __( 'Disables all test IdPs (Demo, Validator, custom URLs). Enable only after joining AgID.', 'auth-spid-cie' ) );
		$this->check_row( 'SPID', 'spid_enabled', $c['spid_enabled'], __( 'Enable login with SPID', 'auth-spid-cie' ) );
		$this->check_row( 'CIE', 'cie_enabled', $c['cie_enabled'], __( 'Enable login with the Electronic Identity Card (CIE)', 'auth-spid-cie' ) );
		$this->select_row( __( 'CIE level', 'auth-spid-cie' ), 'cie_level', $c['cie_level'], array( 1 => __( 'Level 1', 'auth-spid-cie' ), 2 => __( 'Level 2 (recommended)', 'auth-spid-cie' ), 3 => __( 'Level 3', 'auth-spid-cie' ) ), __( 'Assurance level requested for CIE. SPID uses level 2 unless the login link specifies otherwise.', 'auth-spid-cie' ) );
		echo '</table>';

		// --- Ente ---
		echo '<h2>' . esc_html__( '2. Organization (Service Provider)', 'auth-spid-cie' ) . '</h2><table class="form-table" role="presentation">';
		$this->select_row( __( 'Entity type', 'auth-spid-cie' ), 'sp_type', $c['sp_type'], array( 'public' => __( 'Public Administration', 'auth-spid-cie' ), 'private' => __( 'Private entity', 'auth-spid-cie' ) ), __( 'Changes the metadata ContactPerson and the certificate type.', 'auth-spid-cie' ) );
		$this->text_row( 'entityID', 'entity_id', $c['entity_id'], array( 'required' => true, 'class' => 'large-text', 'placeholder' => 'https://servizi.example.it', 'help' => __( 'HTTPS URL that identifies the Service Provider. Once registered with AgID it must not change.', 'auth-spid-cie' ) ) );
		$this->text_row( __( 'Service name', 'auth-spid-cie' ), 'sp_name', $c['sp_name'], array( 'help' => __( 'Shown in the metadata (AttributeConsumingService).', 'auth-spid-cie' ) ) );
		$this->text_row( __( 'Service description', 'auth-spid-cie' ), 'sp_description', $c['sp_description'], array( 'class' => 'large-text' ) );
		$this->text_row( 'Nome organizzazione', 'org_name', $c['org_name'], array( 'required' => true, 'help' => __( 'Full legal name. Used in OrganizationName, Company and in the certificate.', 'auth-spid-cie' ) ) );
		$this->text_row( __( 'Display name', 'auth-spid-cie' ), 'org_display_name', $c['org_display_name'], array( 'required' => true ) );
		$this->text_row( __( 'Organization URL', 'auth-spid-cie' ), 'org_url', $c['org_url'], array( 'required' => true, 'class' => 'large-text', 'type' => 'url', 'placeholder' => 'https://www.example.it' ) );
		if ( $private ) {
			$this->select_row( __( 'Code type', 'auth-spid-cie' ), 'org_code_type', $c['org_code_type'], array( 'VATNumber' => __( 'VAT number', 'auth-spid-cie' ), 'FiscalCode' => __( 'Tax code', 'auth-spid-cie' ) ) );
			$this->text_row( __( 'VAT number / Tax code', 'auth-spid-cie' ), 'org_code', $c['org_code'], array( 'required' => true, 'help' => __( 'Enter the VAT number without prefix (IT is added in the metadata).', 'auth-spid-cie' ) ) );
		} else {
			$this->text_row( __( 'IPA code', 'auth-spid-cie' ), 'org_code', $c['org_code'], array( 'required' => true, 'help' => __( 'The entity\'s iPA code (e.g. c_h501).', 'auth-spid-cie' ) ) );
		}
		$this->text_row( __( 'Country (ISO 3166-1)', 'auth-spid-cie' ), 'country', $c['country'], array( 'class' => 'small-text' ) );
		$this->text_row( __( 'Locality', 'auth-spid-cie' ), 'locality', $c['locality'], array( 'required' => true, 'help' => __( 'Used in the certificate.', 'auth-spid-cie' ) ) );
		$this->text_row( __( 'Contact email', 'auth-spid-cie' ), 'contact_email', $c['contact_email'], array( 'required' => true, 'type' => 'email' ) );
		$this->text_row( __( 'Contact phone', 'auth-spid-cie' ), 'contact_phone', $c['contact_phone'], array( 'required' => true, 'placeholder' => '+39 06 12345678' ) );
		echo '</table>';

		// --- Fatturazione (privati) ---
		echo '<h2>' . esc_html__( '3. Billing data', 'auth-spid-cie' ) . ' ' . ( $private ? '' : '<small>' . esc_html__( '(private entities only: not needed for public administrations)', 'auth-spid-cie' ) . '</small>' ) . '</h2>';
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
		echo '</table>';

		// --- CIE ---
		echo '<h2>' . esc_html__( '4. CIE data', 'auth-spid-cie' ) . '</h2><table class="form-table" role="presentation">';
		if ( $private ) {
			$this->text_row( __( 'Tax code', 'auth-spid-cie' ), 'cie_fiscal_code', $c['cie_fiscal_code'], array( 'help' => __( 'Required for private entities.', 'auth-spid-cie' ) ) );
			$this->text_row( __( 'ATECO / NACE2 code', 'auth-spid-cie' ), 'cie_nace2', $c['cie_nace2'], array( 'class' => 'small-text', 'help' => __( 'Required for private entities (e.g. 84.11).', 'auth-spid-cie' ) ) );
		}
		$this->text_row( __( 'Municipality ISTAT code', 'auth-spid-cie' ), 'cie_municipality', $c['cie_municipality'], array( 'class' => 'small-text', 'help' => __( 'E.g. 058091 for Rome.', 'auth-spid-cie' ) ) );
		$this->text_row( __( 'Province code', 'auth-spid-cie' ), 'cie_province', $c['cie_province'], array( 'class' => 'small-text' ) );
		echo '</table>';

		// --- Attributi ---
		echo '<h2>' . esc_html__( '5. Requested attributes', 'auth-spid-cie' ) . '</h2><p class="description">' . esc_html__( 'All selected attributes must be returned by the IdP, otherwise the login is rejected. The tax code is always required. CIE only returns tax code, first name, last name and date of birth.', 'auth-spid-cie' ) . '</p>';
		echo '<table class="form-table" role="presentation"><tr><th scope="row">' . esc_html__( 'SPID attributes', 'auth-spid-cie' ) . '</th><td>';
		foreach ( OptionsManager::attributes_catalog() as $attr => $def ) {
			printf(
				'<label style="display:inline-block;min-width:260px"><input type="checkbox" name="%s[attributes][]" value="%s" %s %s /> %s <code>%s</code></label><br />',
				esc_attr( $name ),
				esc_attr( $attr ),
				checked( in_array( $attr, (array) $c['attributes'], true ), true, false ),
				'fiscalNumber' === $attr ? 'disabled checked' : '',
				esc_html( $def[0] ),
				esc_html( $attr )
			);
		}
		echo '<input type="hidden" name="' . esc_attr( $name ) . '[attributes][]" value="fiscalNumber" />';
		echo '</td></tr>';
		$this->text_row( 'AttributeConsumingServiceIndex', 'acs_index', $c['acs_index'], array( 'type' => 'number', 'class' => 'small-text', 'help' => __( 'Index of the attribute set in the metadata (normally 0).', 'auth-spid-cie' ) ) );
		echo '</table>';

		// --- Avanzate / test ---
		echo '<h2>' . esc_html__( '6. Testing and advanced options', 'auth-spid-cie' ) . '</h2><table class="form-table" role="presentation">';
		$this->select_row( __( 'Request Destination', 'auth-spid-cie' ), 'destination_mode', $c['destination_mode'], array( 'entity_id' => __( 'IdP entityID (like spid-php)', 'auth-spid-cie' ), 'sso_url' => __( 'SSO service URL', 'auth-spid-cie' ) ), __( 'Change only if the AgID validator requires it.', 'auth-spid-cie' ) );
		$this->check_row( __( 'SPID Demo IdP', 'auth-spid-cie' ), 'test_demo', $c['test_demo'], __( 'demo.spid.gov.it (only when not in production)', 'auth-spid-cie' ) );
		$this->check_row( __( 'SPID Demo (Validator mode)', 'auth-spid-cie' ), 'test_demo_validator', $c['test_demo_validator'], 'demo.spid.gov.it/validator' );
		$this->check_row( 'AgID Validator', 'test_validator', $c['test_validator'], 'validator.spid.gov.it' );
		echo '<tr><th scope="row"><label for="wpspid_test_idp_urls">' . esc_html__( 'Custom test IdPs', 'auth-spid-cie' ) . '</label></th><td><textarea id="wpspid_test_idp_urls" name="' . esc_attr( $name ) . '[test_idp_urls]" rows="3" class="large-text code" placeholder="https://localhost:8443/metadata.xml">' . esc_textarea( implode( "\n", (array) $c['test_idp_urls'] ) ) . '</textarea><p class="description">' . esc_html__( 'One metadata URL (https) per line, max 5. Example: a local spid-saml-check.', 'auth-spid-cie' ) . '</p></td></tr>';
		echo '<tr><th scope="row"><label for="wpspid_test_idp_xml">' . esc_html__( 'Test IdP metadata (XML)', 'auth-spid-cie' ) . '</label></th><td><textarea id="wpspid_test_idp_xml" name="' . esc_attr( $name ) . '[test_idp_xml]" rows="4" class="large-text code" placeholder="&lt;EntityDescriptor ...&gt;">' . esc_textarea( (string) $c['test_idp_xml'] ) . '</textarea><p class="description">' . esc_html__( 'Alternative to the URL: paste here the XML metadata of a test IdP (spid-saml-check, spid-sp-test).', 'auth-spid-cie' ) . '</p></td></tr>';
		$this->check_row( __( 'Unverified TLS (testing only)', 'auth-spid-cie' ), 'test_insecure_tls', $c['test_insecure_tls'], __( 'Accepts self-signed certificates from local test IdPs. Never in production.', 'auth-spid-cie' ) );
		echo '</table>';

		submit_button( __( 'Save settings', 'auth-spid-cie' ) );
		echo '</form>';

		$this->render_certificates();

		echo '</div>';
	}

	private function render_status( array $c ) {
		echo '<div class="card" style="max-width:none"><h2 style="margin-top:0">' . esc_html__( 'Status', 'auth-spid-cie' ) . '</h2><table class="widefat striped" style="max-width:900px"><tbody>';
		$probe = Requirements::probe();
		echo '<tr><td><strong>' . esc_html__( 'Server', 'auth-spid-cie' ) . '</strong></td><td>';
		if ( $probe['ok'] ) {
			echo '<span style="color:#00a32a">&#10003; ' . esc_html__( 'OpenSSL is working', 'auth-spid-cie' ) . '</span> (' . esc_html( $probe['openssl_version'] ) . ')';
		} else {
			echo '<span style="color:#b32d2e">&#10007; ' . esc_html__( 'The server does not allow using certificates: SPID/CIE is blocked.', 'auth-spid-cie' ) . '</span><ul style="list-style:disc;margin-left:20px">';
			foreach ( $probe['errors'] as $err ) {
				echo '<li>' . esc_html( $err ) . '</li>';
			}
			echo '</ul>';
		}
		echo '<br /><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline"><input type="hidden" name="action" value="wpspid_probe" />';
		wp_nonce_field( self::NONCE );
		submit_button( __( 'Check again', 'auth-spid-cie' ), 'link', 'submit', false );
		echo '</form></td></tr>';
		echo '<tr><td><strong>' . esc_html__( 'Data', 'auth-spid-cie' ) . '</strong></td><td>' . wp_kses(
			__( 'Keys, certificates and registered metadata are stored in the <strong>WordPress database</strong> (not in files), so updating or reinstalling the plugin does not lose them. They are kept when the plugin is deleted unless <code>WPSPID_REMOVE_DATA_ON_UNINSTALL</code> is set. Database backups contain the private key: to store it encrypted, define <code>WPSPID_SECRET</code> in wp-config.php.', 'auth-spid-cie' ),
			array( 'code' => array(), 'strong' => array() )
		) . '</td></tr>';
		foreach ( array( 'spid' => 'SPID', 'cie' => 'CIE' ) as $service => $label ) {
			if ( empty( $c[ $service . '_enabled' ] ) ) {
				echo '<tr><td><strong>' . esc_html( $label ) . '</strong></td><td>' . esc_html__( 'Disabled', 'auth-spid-cie' ) . '</td></tr>';
				continue;
			}
			$missing = OptionsManager::missing_for_metadata( $c, $service );
			$info    = CertificateManager::info( $service );
			$url     = home_url( '/?wpspid=metadata&service=' . $service );
			echo '<tr><td><strong>' . esc_html( $label ) . '</strong></td><td>';
			if ( $missing ) {
				echo '<span style="color:#b32d2e">&#10007; ' . esc_html__( 'Missing data:', 'auth-spid-cie' ) . '</span> ' . esc_html( implode( ', ', $missing ) ) . '<br />';
			} else {
				echo '<span style="color:#00a32a">&#10003; ' . esc_html__( 'Organization data complete', 'auth-spid-cie' ) . '</span><br />';
			}
			if ( ! $info ) {
				echo '<span style="color:#b32d2e">&#10007; ' . esc_html__( 'Certificate missing', 'auth-spid-cie' ) . '</span> (' . esc_html__( 'generate or import it below', 'auth-spid-cie' ) . ')<br />';
			} else {
				$ok = $info['days_left'] > 30;
				printf(
					'<span style="color:%s">%s %s</span> (%s)<br />',
					$ok ? '#00a32a' : '#b32d2e',
					$ok ? '&#10003;' : '&#9888;',
					esc_html(
						sprintf(
							/* translators: %d: number of days the certificate is still valid. */
							_n( 'Certificate valid for %d more day', 'Certificate valid for %d more days', (int) $info['days_left'], 'auth-spid-cie' ),
							(int) $info['days_left']
						)
					),
					esc_html(
						sprintf(
							/* translators: %s: expiry date. */
							__( 'expires on %s', 'auth-spid-cie' ),
							wp_date( get_option( 'date_format' ), $info['valid_to'] )
						)
					)
				);
			}
			if ( $info ) {
				$this->render_key_state( $service );
			}
			if ( ! $missing && $info ) {
				echo '<a href="' . esc_url( $url ) . '" target="_blank" rel="noopener">' . esc_html( sprintf( /* translators: %s: SPID or CIE. */ __( '%s metadata', 'auth-spid-cie' ), $label ) ) . '</a> <code>' . esc_html( $url ) . '</code>';
				$this->render_snapshot( $service );
			}
			echo '</td></tr>';
		}
		echo '<tr><td><strong>' . esc_html__( 'Routes', 'auth-spid-cie' ) . '</strong></td><td>ACS: <code>' . esc_html( Config::acs_url() ) . '</code><br />' . esc_html__( 'Logout:', 'auth-spid-cie' ) . ' <code>' . esc_html( Config::slo_url() ) . '</code></td></tr>';
		echo '<tr><td><strong>' . esc_html__( 'Environment', 'auth-spid-cie' ) . '</strong></td><td>' . ( Config::is_production() ? '<strong style="color:#b32d2e">' . esc_html__( 'PRODUCTION', 'auth-spid-cie' ) . '</strong>' : esc_html__( 'Test (test IdPs are visible)', 'auth-spid-cie' ) ) . '</td></tr>';
		echo '</tbody></table>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin-top:10px"><input type="hidden" name="action" value="wpspid_refresh" />';
		wp_nonce_field( self::NONCE );
		submit_button( __( 'Refresh Identity Provider list', 'auth-spid-cie' ), 'secondary', 'submit', false );
		echo '</form></div>';
	}

	private function render_key_state( $service ) {
		$state = CertificateManager::key_state( $service );
		$st    = $state['status'];
		if ( KeyVault::S_OK === $st ) {
			echo '<span style="color:#00a32a">&#10003; ' . esc_html__( 'Private key stored encrypted (WPSPID_SECRET).', 'auth-spid-cie' ) . '</span><br />';
		} elseif ( KeyVault::S_PLAIN === $st ) {
			echo '<span style="color:#996800">&#9888; ' . esc_html__( 'Private key stored in the database WITHOUT encryption: database backups contain it. To encrypt it, define WPSPID_SECRET in wp-config.php (see the documentation).', 'auth-spid-cie' ) . '</span><br />';
		} elseif ( KeyVault::S_PLAIN_PENDING === $st ) {
			echo '<span style="color:#996800">&#9888; ' . esc_html__( 'WPSPID_SECRET is defined but the private key is still stored without encryption.', 'auth-spid-cie' ) . '</span> ';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline"><input type="hidden" name="action" value="wpspid_encrypt_key" /><input type="hidden" name="service" value="' . esc_attr( $service ) . '" />';
			wp_nonce_field( self::NONCE );
			submit_button( __( 'Encrypt now', 'auth-spid-cie' ), 'link', 'submit', false );
			echo '</form><br />';
		} else {
			echo '<span style="color:#b32d2e">&#10007; ' . esc_html( KeyVault::message( $st ) ) . '</span><br />';
		}
	}

	private function render_snapshot( $service ) {
		try {
			$status = MetadataSnapshot::status( $service, MetadataBuilder::generate( $service ) );
		} catch ( \Exception $e ) {
			return;
		}
		$dl = function ( $which ) use ( $service ) {
			return wp_nonce_url( admin_url( 'admin-post.php?action=wpspid_meta_download&service=' . $service . '&which=' . $which ), self::NONCE );
		};
		echo '<div style="margin-top:8px">';
		if ( 'none' === $status['state'] ) {
			echo '<span style="color:#996800">&#9888; ' . esc_html__( 'You have not saved the registered metadata yet.', 'auth-spid-cie' ) . '</span> ' . esc_html__( 'After registering the metadata with AgID/CIE, save it here: you will be warned if it changes.', 'auth-spid-cie' ) ;
		} elseif ( 'same' === $status['state'] ) {
			echo '<span style="color:#00a32a">&#10003; ' . esc_html(
				sprintf(
					/* translators: %s: date the metadata was saved as registered. */
					__( 'Same as the metadata registered on %s', 'auth-spid-cie' ),
					wp_date( get_option( 'date_format' ), strtotime( $status['saved_at'] ) )
				)
			) . '</span>' . ( $status['note'] ? ' (' . esc_html( $status['note'] ) . ')' : '' );
		} else {
			echo '<span style="color:#b32d2e">&#9888; ' . esc_html(
				sprintf(
					/* translators: %s: date the metadata was saved as registered. */
					__( 'Different from the metadata registered on %s', 'auth-spid-cie' ),
					wp_date( get_option( 'date_format' ), strtotime( $status['saved_at'] ) )
				)
			) . '</span>. ' . wp_kses( __( 'If the change is intended you must <strong>repeat the registration</strong> with AgID/CIE, then save the new one.', 'auth-spid-cie' ), array( 'strong' => array() ) );
		}
		echo '<br /><a class="button" href="' . esc_url( $dl( 'current' ) ) . '">' . esc_html__( 'Download current metadata', 'auth-spid-cie' ) . '</a> ';
		if ( 'none' !== $status['state'] ) {
			echo '<a class="button" href="' . esc_url( $dl( 'registered' ) ) . '">' . esc_html__( 'Download the registered one', 'auth-spid-cie' ) . '</a> ';
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline-block"><input type="hidden" name="action" value="wpspid_meta_snapshot" /><input type="hidden" name="service" value="' . esc_attr( $service ) . '" />';
		wp_nonce_field( self::NONCE );
		echo '<input type="text" name="note" placeholder="' . esc_attr__( 'Note (e.g. registered on ...)', 'auth-spid-cie' ) . '" class="regular-text" /> ';
		submit_button( 'none' === $status['state'] ? __( 'Save as registered', 'auth-spid-cie' ) : __( 'Save the current one as registered', 'auth-spid-cie' ), 'secondary', 'submit', false );
		echo '</form></div>';
	}

	private function render_certificates() {
		echo '<h2>' . esc_html__( '7. Service Provider certificates', 'auth-spid-cie' ) . '</h2><p class="description">' . wp_kses( __( 'The certificate signs requests and metadata. If you have already registered an SP with AgID/CIE, <strong>import</strong> the existing key and certificate instead of generating new ones, otherwise you will have to repeat the registration. The private key is never shown.', 'auth-spid-cie' ), array( 'strong' => array() ) ) . '</p>';
		$probe = Requirements::probe();
		if ( ! $probe['ok'] ) {
			echo '<div class="notice notice-error inline"><p><strong>' . esc_html__( 'Certificate generation and import are not available:', 'auth-spid-cie' ) . '</strong> ' . esc_html( implode( ' ', $probe['errors'] ) ) . '</p></div>';
			return;
		}
		foreach ( array( 'spid' => 'SPID', 'cie' => 'CIE' ) as $service => $label ) {
			$info = CertificateManager::info( $service );
			echo '<div class="card" style="max-width:none"><h3 style="margin-top:0">' . esc_html( $label ) . '</h3>';
			if ( $info ) {
				echo '<p>' . esc_html__( 'Subject:', 'auth-spid-cie' ) . ' <code>' . esc_html( $info['subject'] ) . '</code> &middot; ' . esc_html__( 'Identifier:', 'auth-spid-cie' ) . ' <code>' . esc_html( $info['organization_identifier'] ) . '</code><br />SHA-256: <code>' . esc_html( $info['fingerprint'] ) . '</code></p>';
				$dl = wp_nonce_url( admin_url( 'admin-post.php?action=wpspid_cert_download&service=' . $service ), self::NONCE );
				echo '<p><a class="button" href="' . esc_url( $dl ) . '>' . esc_html__( 'Download certificate (.crt)', 'auth-spid-cie' ) . '</a></p>';
			}
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="wpspid_cert_generate" /><input type="hidden" name="service" value="' . esc_attr( $service ) . '" />';
			wp_nonce_field( self::NONCE );
			if ( $info ) {
				echo '<label><input type="checkbox" name="confirm_replace" value="1" /> ' . esc_html__( 'I confirm: replace the existing certificate', 'auth-spid-cie' ) . '</label> ';
			}
			submit_button( $info ? __( 'Regenerate', 'auth-spid-cie' ) : __( 'Generate certificate', 'auth-spid-cie' ), 'primary', 'submit', false );
			echo '</form>';
			echo '<details style="margin-top:12px"><summary>' . esc_html__( 'Import existing key and certificate', 'auth-spid-cie' ) . '</summary>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="wpspid_cert_import" /><input type="hidden" name="service" value="' . esc_attr( $service ) . '" />';
			wp_nonce_field( self::NONCE );
			echo '<p><label>' . esc_html__( 'Private key (PEM)', 'auth-spid-cie' ) . '<br /><textarea name="import_key" rows="5" class="large-text code" autocomplete="off" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label></p>';
			echo '<p><label>' . esc_html__( 'Certificate (PEM)', 'auth-spid-cie' ) . '<br /><textarea name="import_cert" rows="5" class="large-text code" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label></p>';
			if ( $info ) {
				echo '<p><label><input type="checkbox" name="confirm_replace" value="1" /> ' . esc_html__( 'I confirm: replace the existing certificate', 'auth-spid-cie' ) . '</label></p>';
			}
			submit_button( __( 'Import', 'auth-spid-cie' ), 'secondary', 'submit', false );
			echo '</form></details></div>';
		}
	}
}
