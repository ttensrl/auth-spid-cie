<?php
namespace WpSpidCie\Settings;

use WpSpidCie\Cert\CertificateManager;
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
		add_action( 'admin_post_wpspid_meta_snapshot', array( $this, 'post_meta_snapshot' ) );
		add_action( 'admin_post_wpspid_meta_download', array( $this, 'post_meta_download' ) );
	}

	public function add_menu() {
		add_options_page(
			__( 'SPID / CIE', 'wp-spid-cie' ),
			__( 'SPID / CIE', 'wp-spid-cie' ),
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
			wp_die( esc_html__( 'Permessi insufficienti.', 'wp-spid-cie' ), 403 );
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
			$this->back( 'error', 'Generazione bloccata: ' . implode( ' ', $probe['errors'] ) );
		}

		if ( CertificateManager::exists( $service ) && empty( $_POST['confirm_replace'] ) ) {
			$this->back( 'error', 'Esiste già un certificato: spunta la conferma per sostituirlo (andrà ri-registrato il metadata).' );
		}
		$c       = Config::options();
		$missing = array();
		foreach ( array( 'entity_id' => 'entityID', 'org_name' => 'Nome organizzazione', 'org_display_name' => 'Nome visualizzato', 'org_code' => 'Codice IPA/P.IVA/CF', 'locality' => 'Località' ) as $k => $label ) {
			if ( '' === trim( (string) $c[ $k ] ) ) {
				$missing[] = $label;
			}
		}
		if ( $missing ) {
			$this->back( 'error', 'Compila e salva prima: ' . implode( ', ', $missing ) . '.' );
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
			error_log( '[wp-spid-cie] cert generate: ' . $e->getMessage() );
			$this->back( 'error', 'Generazione del certificato non riuscita: ' . $e->getMessage() );
		}
		$this->back( 'success', 'Certificato ' . strtoupper( $service ) . ' generato (validità 730 giorni).' );
	}

	public function post_cert_import() {
		$this->guard( self::NONCE );
		$service = $this->service_from_post();
		$errors  = Requirements::check();
		if ( $errors ) {
			$this->back( 'error', 'Import bloccato: ' . implode( ' ', $errors ) );
		}
		$key     = isset( $_POST['import_key'] ) ? trim( wp_unslash( $_POST['import_key'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- PEM, validated by OpenSSL.
		$cert    = isset( $_POST['import_cert'] ) ? trim( wp_unslash( $_POST['import_cert'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

		if ( CertificateManager::exists( $service ) && empty( $_POST['confirm_replace'] ) ) {
			$this->back( 'error', 'Esiste già un certificato: spunta la conferma per sostituirlo.' );
		}
		if ( '' === $key || '' === $cert ) {
			$this->back( 'error', 'Incolla sia la chiave privata sia il certificato (formato PEM).' );
		}
		try {
			CertificateManager::import( $service, $key, $cert );
		} catch ( \Exception $e ) {
			$this->back( 'error', 'Import non riuscito: ' . $e->getMessage() );
		}
		$this->back( 'success', 'Certificato e chiave ' . strtoupper( $service ) . ' importati.' );
	}

	public function post_cert_download() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permessi insufficienti.', 'wp-spid-cie' ), 403 );
		}
		check_admin_referer( self::NONCE );
		$service = $this->service_from_post();
		$pem     = CertificateManager::get_certificate( $service );
		if ( ! $pem ) {
			wp_die( esc_html__( 'Certificato non presente.', 'wp-spid-cie' ), 404 );
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
		$this->back( $probe['ok'] ? 'success' : 'error', $probe['ok'] ? 'Verifica superata: il server può generare e usare i certificati.' : 'Verifica fallita: ' . implode( ' ', $probe['errors'] ) );
	}

	public function post_meta_snapshot() {
		$this->guard( self::NONCE );
		$service = $this->service_from_post();
		$note    = isset( $_POST['note'] ) ? sanitize_text_field( wp_unslash( $_POST['note'] ) ) : '';
		try {
			MetadataSnapshot::save( $service, MetadataBuilder::generate( $service ), $note );
		} catch ( \Exception $e ) {
			$this->back( 'error', 'Non salvato: ' . $e->getMessage() );
		}
		$this->back( 'success', 'Metadata ' . strtoupper( $service ) . ' salvato come "registrato".' );
	}

	public function post_meta_download() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permessi insufficienti.', 'wp-spid-cie' ), 403 );
		}
		check_admin_referer( self::NONCE );
		$service = $this->service_from_post();
		$which   = isset( $_GET['which'] ) && 'registered' === $_GET['which'] ? 'registered' : 'current'; // phpcs:ignore WordPress.Security.NonceVerification -- checked above.
		try {
			if ( 'registered' === $which ) {
				$saved = MetadataSnapshot::get( $service );
				if ( ! $saved ) {
					wp_die( esc_html__( 'Nessun metadata registrato salvato.', 'wp-spid-cie' ), 404 );
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
		header( 'Content-Disposition: attachment; filename="metadata-' . $service . ( 'registered' === $which ? '-registrato' : '' ) . '.xml"' );
		echo $xml; // phpcs:ignore WordPress.Security.EscapeOutput -- signed XML metadata.
		exit;
	}

	public function post_refresh() {
		$this->guard( self::NONCE );
		Registry::get_instance()->refresh();
		CieMetadata::refresh();
		TestIdps::refresh();
		$this->back( 'success', 'Cache degli Identity Provider svuotata: verrà ricaricata al prossimo utilizzo.' );
	}

	// ------------------------------------------------------------------ rendering

	private function text_row( $label, $name, $value, $args = array() ) {
		$args = array_merge( array( 'type' => 'text', 'class' => 'regular-text', 'help' => '', 'placeholder' => '', 'required' => false ), $args );
		echo '<tr><th scope="row"><label for="wpspid_' . esc_attr( $name ) . '">' . esc_html( $label ) . ( $args['required'] ? ' <span style="color:#b32d2e">*</span>' : '' ) . '</label></th><td>';
		// .small-text di WordPress e' largo 50px: tronca CAP (5 cifre) e codice ISTAT (6 cifre).
		$style = false !== strpos( $args['class'], 'small-text' ) ? ' style="width:8em"' : '';
		printf(
			'<input type="%s" id="wpspid_%s" name="%s[%s]" value="%s" class="%s" placeholder="%s"' . $style . ' />',
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

		echo '<div class="wrap"><h1>' . esc_html__( 'SPID / CIE', 'wp-spid-cie' ) . '</h1>';
		if ( $notice ) {
			printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', 'success' === $notice[0] ? 'success' : 'error', esc_html( $notice[1] ) );
		}
		settings_errors( OptionsManager::OPTION );

		$this->render_status( $c );

		echo '<form action="options.php" method="post">';
		settings_fields( self::GROUP );
		echo '<input type="hidden" name="' . esc_attr( $name ) . '[_form]" value="1" />';

		// --- Generale ---
		echo '<h2>1. Generale</h2><table class="form-table" role="presentation">';
		$this->check_row( 'Attiva l\'accesso', 'enabled', $c['enabled'], 'Abilita le rotte di login/ACS (il metadata resta sempre raggiungibile)' );
		$this->check_row( 'Ambiente di produzione', 'production', $c['production'], 'Disattiva tutti gli IdP di test (Demo, Validator, URL personalizzati). Attivare solo dopo l\'adesione ad AgID.' );
		$this->check_row( 'SPID', 'spid_enabled', $c['spid_enabled'], 'Abilita l\'accesso con SPID' );
		$this->check_row( 'CIE', 'cie_enabled', $c['cie_enabled'], 'Abilita l\'accesso con Carta d\'Identità Elettronica' );
		$this->select_row( 'Livello CIE', 'cie_level', $c['cie_level'], array( 1 => 'Livello 1', 2 => 'Livello 2 (consigliato)', 3 => 'Livello 3' ), 'Livello di garanzia richiesto per la CIE. SPID usa il livello 2 se non indicato dal link di login.' );
		echo '</table>';

		// --- Ente ---
		echo '<h2>2. Ente (Service Provider)</h2><table class="form-table" role="presentation">';
		$this->select_row( 'Tipo di ente', 'sp_type', $c['sp_type'], array( 'public' => 'Pubblica Amministrazione', 'private' => 'Soggetto privato' ), 'Cambia ContactPerson del metadata e il tipo di certificato.' );
		$this->text_row( 'entityID', 'entity_id', $c['entity_id'], array( 'required' => true, 'class' => 'large-text', 'placeholder' => 'https://servizi.example.it', 'help' => 'URL https che identifica il Service Provider. Una volta registrato presso AgID non va più cambiato.' ) );
		$this->text_row( 'Nome del servizio', 'sp_name', $c['sp_name'], array( 'help' => 'Mostrato nel metadata (AttributeConsumingService).' ) );
		$this->text_row( 'Descrizione del servizio', 'sp_description', $c['sp_description'], array( 'class' => 'large-text' ) );
		$this->text_row( 'Nome organizzazione', 'org_name', $c['org_name'], array( 'required' => true, 'help' => 'Ragione sociale completa. Usato in OrganizationName, Company e nel certificato.' ) );
		$this->text_row( 'Nome visualizzato', 'org_display_name', $c['org_display_name'], array( 'required' => true ) );
		$this->text_row( 'URL organizzazione', 'org_url', $c['org_url'], array( 'required' => true, 'class' => 'large-text', 'type' => 'url', 'placeholder' => 'https://www.example.it' ) );
		if ( $private ) {
			$this->select_row( 'Tipo di codice', 'org_code_type', $c['org_code_type'], array( 'VATNumber' => 'Partita IVA', 'FiscalCode' => 'Codice fiscale' ) );
			$this->text_row( 'Partita IVA / Codice fiscale', 'org_code', $c['org_code'], array( 'required' => true, 'help' => 'La P.IVA va indicata senza prefisso (viene aggiunto IT nel metadata).' ) );
		} else {
			$this->text_row( 'Codice IPA', 'org_code', $c['org_code'], array( 'required' => true, 'help' => 'Codice iPA dell\'ente (es. c_h501).' ) );
		}
		$this->text_row( 'Paese (ISO 3166-1)', 'country', $c['country'], array( 'class' => 'small-text' ) );
		$this->text_row( 'Località', 'locality', $c['locality'], array( 'required' => true, 'help' => 'Usata nel certificato.' ) );
		$this->text_row( 'Email di contatto', 'contact_email', $c['contact_email'], array( 'required' => true, 'type' => 'email' ) );
		$this->text_row( 'Telefono di contatto', 'contact_phone', $c['contact_phone'], array( 'required' => true, 'placeholder' => '+39 06 12345678' ) );
		echo '</table>';

		// --- Fatturazione (privati) ---
		echo '<h2>3. Dati di fatturazione ' . ( $private ? '' : '<small>(solo per enti privati: non necessari per la PA)</small>' ) . '</h2>';
		echo '<p class="description">Avviso SPID n.29 v.3: <code>CessionarioCommittente</code> nel metadata dei privati.</p><table class="form-table" role="presentation">';
		$this->text_row( 'IdPaese', 'fpa_id_paese', $c['fpa_id_paese'], array( 'class' => 'small-text' ) );
		$this->text_row( 'IdCodice', 'fpa_id_codice', $c['fpa_id_codice'] );
		$this->text_row( 'Denominazione', 'fpa_denominazione', $c['fpa_denominazione'] );
		$this->text_row( 'Indirizzo', 'fpa_indirizzo', $c['fpa_indirizzo'] );
		$this->text_row( 'Numero civico', 'fpa_numero_civico', $c['fpa_numero_civico'], array( 'class' => 'small-text' ) );
		$this->text_row( 'CAP', 'fpa_cap', $c['fpa_cap'], array( 'class' => 'small-text' ) );
		$this->text_row( 'Comune', 'fpa_comune', $c['fpa_comune'] );
		$this->text_row( 'Provincia', 'fpa_provincia', $c['fpa_provincia'], array( 'class' => 'small-text' ) );
		$this->text_row( 'Nazione', 'fpa_nazione', $c['fpa_nazione'], array( 'class' => 'small-text' ) );
		$this->text_row( 'Ragione sociale (contatto)', 'fpa_org_name', $c['fpa_org_name'] );
		$this->text_row( 'Email (contatto)', 'fpa_email', $c['fpa_email'], array( 'type' => 'email' ) );
		$this->text_row( 'Telefono (contatto)', 'fpa_phone', $c['fpa_phone'] );
		echo '</table>';

		// --- CIE ---
		echo '<h2>4. Dati per la CIE</h2><table class="form-table" role="presentation">';
		if ( $private ) {
			$this->text_row( 'Codice fiscale', 'cie_fiscal_code', $c['cie_fiscal_code'], array( 'help' => 'Obbligatorio per i privati.' ) );
			$this->text_row( 'Codice ATECO / NACE2', 'cie_nace2', $c['cie_nace2'], array( 'class' => 'small-text', 'help' => 'Obbligatorio per i privati (es. 84.11).' ) );
		}
		$this->text_row( 'Codice ISTAT del comune', 'cie_municipality', $c['cie_municipality'], array( 'class' => 'small-text', 'help' => 'Es. 058091 per Roma.' ) );
		$this->text_row( 'Sigla provincia', 'cie_province', $c['cie_province'], array( 'class' => 'small-text' ) );
		echo '</table>';

		// --- Attributi ---
		echo '<h2>5. Attributi richiesti</h2><p class="description">Tutti gli attributi selezionati devono essere restituiti dall\'IdP, altrimenti l\'accesso viene rifiutato. Il codice fiscale è sempre richiesto. La CIE restituisce solo codice fiscale, nome, cognome e data di nascita.</p>';
		echo '<table class="form-table" role="presentation"><tr><th scope="row">Attributi SPID</th><td>';
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
		$this->text_row( 'AttributeConsumingServiceIndex', 'acs_index', $c['acs_index'], array( 'type' => 'number', 'class' => 'small-text', 'help' => 'Indice dell\'insieme di attributi nel metadata (di norma 0).' ) );
		echo '</table>';

		// --- Avanzate / test ---
		echo '<h2>6. Test e opzioni avanzate</h2><table class="form-table" role="presentation">';
		$this->select_row( 'Destination della richiesta', 'destination_mode', $c['destination_mode'], array( 'entity_id' => 'entityID dell\'IdP (come spid-php)', 'sso_url' => 'URL del servizio SSO' ), 'Cambiare solo se il validator AgID lo richiede.' );
		$this->check_row( 'IdP SPID Demo', 'test_demo', $c['test_demo'], 'demo.spid.gov.it (solo se non in produzione)' );
		$this->check_row( 'SPID Demo (modalità Validator)', 'test_demo_validator', $c['test_demo_validator'], 'demo.spid.gov.it/validator' );
		$this->check_row( 'AgID Validator', 'test_validator', $c['test_validator'], 'validator.spid.gov.it' );
		echo '<tr><th scope="row"><label for="wpspid_test_idp_urls">IdP di test personalizzati</label></th><td><textarea id="wpspid_test_idp_urls" name="' . esc_attr( $name ) . '[test_idp_urls]" rows="3" class="large-text code" placeholder="https://localhost:8443/metadata.xml">' . esc_textarea( implode( "\n", (array) $c['test_idp_urls'] ) ) . '</textarea><p class="description">Un URL di metadata (https) per riga, max 5. Esempio: lo spid-saml-check locale (vedi docker/).</p></td></tr>';
		echo '<tr><th scope="row"><label for="wpspid_test_idp_xml">Metadata IdP di test (XML)</label></th><td><textarea id="wpspid_test_idp_xml" name="' . esc_attr( $name ) . '[test_idp_xml]" rows="4" class="large-text code" placeholder="&lt;EntityDescriptor ...&gt;">' . esc_textarea( (string) $c['test_idp_xml'] ) . '</textarea><p class="description">In alternativa all\'URL: incolla qui il metadata XML di un IdP di test (spid-saml-check, spid-sp-test).</p></td></tr>';
		$this->check_row( 'TLS non verificato (solo test)', 'test_insecure_tls', $c['test_insecure_tls'], 'Accetta certificati self-signed degli IdP di test locali. Mai in produzione.' );
		echo '</table>';

		submit_button( __( 'Salva impostazioni', 'wp-spid-cie' ) );
		echo '</form>';

		$this->render_certificates();

		echo '</div>';
	}

	private function render_status( array $c ) {
		echo '<div class="card" style="max-width:none"><h2 style="margin-top:0">Stato</h2><table class="widefat striped" style="max-width:900px"><tbody>';
		$probe = Requirements::probe();
		echo '<tr><td><strong>Server</strong></td><td>';
		if ( $probe['ok'] ) {
			echo '<span style="color:#00a32a">&#10003; OpenSSL funzionante</span> (' . esc_html( $probe['openssl_version'] ) . ')';
		} else {
			echo '<span style="color:#b32d2e">&#10007; Il server non permette di usare i certificati: SPID/CIE è bloccato.</span><ul style="list-style:disc;margin-left:20px">';
			foreach ( $probe['errors'] as $err ) {
				echo '<li>' . esc_html( $err ) . '</li>';
			}
			echo '</ul>';
		}
		echo '<br /><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline"><input type="hidden" name="action" value="wpspid_probe" />';
		wp_nonce_field( self::NONCE );
		submit_button( 'Ricontrolla', 'link', 'submit', false );
		echo '</form></td></tr>';
		echo '<tr><td><strong>Dati</strong></td><td>Chiavi, certificati e metadata registrati sono in <code>' . esc_html( CertificateManager::get_storage_dir() ) . '</code>. <strong>Eliminando il plugin si perdono</strong> (e il certificato registrato con AgID/CIE va rifatto): scarica prima il certificato e il metadata registrato.</td></tr>';
		foreach ( array( 'spid' => 'SPID', 'cie' => 'CIE' ) as $service => $label ) {
			if ( empty( $c[ $service . '_enabled' ] ) ) {
				echo '<tr><td><strong>' . esc_html( $label ) . '</strong></td><td>Disattivato</td></tr>';
				continue;
			}
			$missing = OptionsManager::missing_for_metadata( $c, $service );
			$info    = CertificateManager::info( $service );
			$url     = home_url( '/?wpspid=metadata&service=' . $service );
			echo '<tr><td><strong>' . esc_html( $label ) . '</strong></td><td>';
			if ( $missing ) {
				echo '<span style="color:#b32d2e">&#10007; Dati mancanti:</span> ' . esc_html( implode( ', ', $missing ) ) . '<br />';
			} else {
				echo '<span style="color:#00a32a">&#10003; Dati dell\'ente completi</span><br />';
			}
			if ( ! $info ) {
				echo '<span style="color:#b32d2e">&#10007; Certificato assente</span> (generalo o importalo qui sotto)<br />';
			} else {
				$ok = $info['days_left'] > 30;
				printf( '<span style="color:%s">%s Certificato valido ancora %d giorni</span> (scade il %s)<br />', $ok ? '#00a32a' : '#b32d2e', $ok ? '&#10003;' : '&#9888;', (int) $info['days_left'], esc_html( wp_date( get_option( 'date_format' ), $info['valid_to'] ) ) );
			}
			if ( ! $missing && $info ) {
				echo '<a href="' . esc_url( $url ) . '" target="_blank" rel="noopener">Metadata ' . esc_html( $label ) . '</a> <code>' . esc_html( $url ) . '</code>';
				$this->render_snapshot( $service );
			}
			echo '</td></tr>';
		}
		echo '<tr><td><strong>Rotte</strong></td><td>ACS: <code>' . esc_html( Config::acs_url() ) . '</code><br />Logout: <code>' . esc_html( Config::slo_url() ) . '</code></td></tr>';
		echo '<tr><td><strong>Ambiente</strong></td><td>' . ( Config::is_production() ? '<strong style="color:#b32d2e">PRODUZIONE</strong>' : 'Test (gli IdP di test sono visibili)' ) . '</td></tr>';
		echo '</tbody></table>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin-top:10px"><input type="hidden" name="action" value="wpspid_refresh" />';
		wp_nonce_field( self::NONCE );
		submit_button( 'Aggiorna elenco Identity Provider', 'secondary', 'submit', false );
		echo '</form></div>';
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
			echo '<span style="color:#996800">&#9888; Non hai ancora salvato il metadata registrato.</span> Dopo aver registrato il metadata presso AgID/CIE, salvalo qui: ti avviserò se cambia.';
		} elseif ( 'same' === $status['state'] ) {
			echo '<span style="color:#00a32a">&#10003; Uguale al metadata registrato</span> il ' . esc_html( wp_date( get_option( 'date_format' ), strtotime( $status['saved_at'] ) ) ) . ( $status['note'] ? ' (' . esc_html( $status['note'] ) . ')' : '' );
		} else {
			echo '<span style="color:#b32d2e">&#9888; Diverso dal metadata registrato</span> il ' . esc_html( wp_date( get_option( 'date_format' ), strtotime( $status['saved_at'] ) ) ) . '. Se la modifica è voluta devi <strong>ripetere la registrazione</strong> presso AgID/CIE, poi salvare il nuovo.';
		}
		echo '<br /><a class="button" href="' . esc_url( $dl( 'current' ) ) . '">Scarica metadata attuale</a> ';
		if ( 'none' !== $status['state'] ) {
			echo '<a class="button" href="' . esc_url( $dl( 'registered' ) ) . '">Scarica quello registrato</a> ';
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline-block"><input type="hidden" name="action" value="wpspid_meta_snapshot" /><input type="hidden" name="service" value="' . esc_attr( $service ) . '" />';
		wp_nonce_field( self::NONCE );
		echo '<input type="text" name="note" placeholder="Nota (es. registrato il ...)" class="regular-text" /> ';
		submit_button( 'none' === $status['state'] ? 'Salva come registrato' : 'Salva l\'attuale come registrato', 'secondary', 'submit', false );
		echo '</form></div>';
	}

	private function render_certificates() {
		echo '<h2>7. Certificati del Service Provider</h2><p class="description">Il certificato firma richieste e metadata. Se hai già registrato un SP presso AgID/CIE, <strong>importa</strong> chiave e certificato esistenti invece di generarne di nuovi, altrimenti dovrai ripetere la registrazione. La chiave privata non viene mai mostrata.</p>';
		$probe = Requirements::probe();
		if ( ! $probe['ok'] ) {
			echo '<div class="notice notice-error inline"><p><strong>Generazione e import dei certificati non disponibili:</strong> ' . esc_html( implode( ' ', $probe['errors'] ) ) . '</p></div>';
			return;
		}
		foreach ( array( 'spid' => 'SPID', 'cie' => 'CIE' ) as $service => $label ) {
			$info = CertificateManager::info( $service );
			echo '<div class="card" style="max-width:none"><h3 style="margin-top:0">' . esc_html( $label ) . '</h3>';
			if ( $info ) {
				echo '<p>Soggetto: <code>' . esc_html( $info['subject'] ) . '</code> &middot; Identificativo: <code>' . esc_html( $info['organization_identifier'] ) . '</code><br />SHA-256: <code>' . esc_html( $info['fingerprint'] ) . '</code></p>';
				$dl = wp_nonce_url( admin_url( 'admin-post.php?action=wpspid_cert_download&service=' . $service ), self::NONCE );
				echo '<p><a class="button" href="' . esc_url( $dl ) . '">Scarica certificato (.crt)</a></p>';
			}
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="wpspid_cert_generate" /><input type="hidden" name="service" value="' . esc_attr( $service ) . '" />';
			wp_nonce_field( self::NONCE );
			if ( $info ) {
				echo '<label><input type="checkbox" name="confirm_replace" value="1" /> Confermo: sostituisci il certificato esistente</label> ';
			}
			submit_button( $info ? 'Rigenera' : 'Genera certificato', 'primary', 'submit', false );
			echo '</form>';
			echo '<details style="margin-top:12px"><summary>Importa chiave e certificato esistenti</summary>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="wpspid_cert_import" /><input type="hidden" name="service" value="' . esc_attr( $service ) . '" />';
			wp_nonce_field( self::NONCE );
			echo '<p><label>Chiave privata (PEM)<br /><textarea name="import_key" rows="5" class="large-text code" autocomplete="off" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label></p>';
			echo '<p><label>Certificato (PEM)<br /><textarea name="import_cert" rows="5" class="large-text code" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label></p>';
			if ( $info ) {
				echo '<p><label><input type="checkbox" name="confirm_replace" value="1" /> Confermo: sostituisci il certificato esistente</label></p>';
			}
			submit_button( 'Importa', 'secondary', 'submit', false );
			echo '</form></details></div>';
		}
	}
}
