<?php
// phpcs:disable WordPress.Security.NonceVerification.Recommended -- endpoint pubblici di login SPID/CIE: parametri GET di sola lettura, l'autenticita' viene dalla firma SAML.
namespace AuthSpidCie\Http;

use AuthSpidCie\Auth\SessionGate;
use AuthSpidCie\Idp\IdpRepository;
use AuthSpidCie\Saml\AuthnRequestBuilder;
use AuthSpidCie\Saml\Bindings;
use AuthSpidCie\Saml\ResponseValidator;
use AuthSpidCie\Saml\ValidationException;
use AuthSpidCie\State\ReplayCache;
use AuthSpidCie\State\RequestStore;
use AuthSpidCie\Support\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles plugin routing via query vars (?authspidcie=choose|login|acs|slo|metadata).
 */
class Router {
	private static $instance = null;

	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'query_vars', array( $this, 'add_query_vars' ) );
		add_action( 'template_redirect', array( $this, 'handle_requests' ), 1 );
	}

	public function add_query_vars( $vars ) {
		$vars[] = 'authspidcie';
		$vars[] = 'service';
		return $vars;
	}

	public function handle_requests() {
		$action = get_query_var( 'authspidcie' );
		if ( ! $action ) {
			return;
		}

		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals -- costante standard letta dai plugin di cache
		}
		nocache_headers();

		switch ( $action ) {
			case 'choose':
				$this->handle_choose();
				break;
			case 'login':
				$this->handle_login();
				break;
			case 'acs':
				$this->handle_acs();
				break;
			case 'slo':
				$this->handle_slo();
				break;
			case 'metadata':
				$this->handle_metadata();
				break;
		}
	}

	private function fail( $message, $status = 400 ) {
		wp_die( esc_html( $message ), esc_html__( 'SPID/CIE error', 'auth-spid-cie' ), array( 'response' => (int) $status, 'back_link' => true ) );
	}

	/** Pick endpoint: CIE always POST; SPID prefers Redirect, falls back to POST. */
	private function pick_endpoint( array $idp ) {
		$want = ( 'cie' === $idp['type'] ) ? array( 'post' ) : array( 'redirect', 'post' );
		foreach ( $want as $kind ) {
			foreach ( $idp['sso'] as $ep ) {
				$is_redirect = false !== strpos( $ep['binding'], 'HTTP-Redirect' );
				$is_post     = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' === $ep['binding'];
				if ( ( 'redirect' === $kind && $is_redirect ) || ( 'post' === $kind && $is_post ) ) {
					if ( 0 === strpos( $ep['location'], 'https://' ) ) {
						return array( $ep['location'], $kind );
					}
				}
			}
		}
		return array( '', '' );
	}

	private function require_enabled() {
		if ( ! Config::is_enabled() ) {
			$this->fail( __( 'SPID/CIE login is not enabled.', 'auth-spid-cie' ), 503 );
		}
	}

	/** Pagina di accesso: scelta tra SPID e CIE, dentro l'header e il footer del tema. */
	private function handle_choose() {
		$this->require_enabled();
		$return = isset( $_GET['returnTo'] ) ? wp_validate_redirect( esc_url_raw( wp_unslash( $_GET['returnTo'] ) ), '' ) : '';
		status_header( 200 );
		add_filter( 'pre_get_document_title', function () {
			return __( 'Log in with SPID or CIE', 'auth-spid-cie' ) . ' - ' . get_bloginfo( 'name' );
		} );
		add_filter( 'body_class', function ( $classes ) {
			$classes[] = 'authspidcie-choose';
			return $classes;
		} );
		\AuthSpidCie\Ui\Buttons::enqueue();
		$this->make_virtual_page( __( 'Log in with SPID or CIE', 'auth-spid-cie' ) );
		get_header();
		echo '<main id="main-content" class="authspidcie-main">' . \AuthSpidCie\Ui\Buttons::page( array( 'return' => $return ) ) . '</main>'; // phpcs:ignore WordPress.Security.EscapeOutput -- every part is escaped in Buttons.
		get_footer();
		exit;
	}

	/**
	 * Fa passare la richiesta per una pagina WordPress "virtuale" (nessun record nel database), cosi'
	 * breadcrumb, titolo e classi del tema parlano della pagina di accesso e non della home o del blog.
	 */
	private function make_virtual_page( $title ) {
		global $wp_query, $post;
		$post = new \WP_Post( (object) array(
			'ID'          => 0,
			'post_type'   => 'page',
			'post_status' => 'publish',
			'post_title'  => $title,
			'post_name'   => 'accedi-spid-cie',
			'filter'      => 'raw',
		) );
		$wp_query->post                  = $post;
		$wp_query->posts                 = array( $post );
		$wp_query->post_count            = 1;
		$wp_query->found_posts           = 1;
		$wp_query->queried_object        = $post;
		$wp_query->queried_object_id     = 0;
		$wp_query->is_page               = true;
		$wp_query->is_singular           = true;
		$wp_query->is_home               = false;
		$wp_query->is_posts_page         = false;
		$wp_query->is_404                = false;
		setup_postdata( $post );
	}

	private function handle_login() {
		$this->require_enabled();
		$idp_entity_id = isset( $_GET['idp'] ) ? sanitize_text_field( wp_unslash( $_GET['idp'] ) ) : '';
		if ( '' === $idp_entity_id ) {
			$this->fail( __( 'IdP not specified.', 'auth-spid-cie' ) );
		}
		$idp = IdpRepository::find_by_entity_id( $idp_entity_id );
		if ( ! $idp ) {
			$this->fail( __( 'IdP not found.', 'auth-spid-cie' ) );
		}
		if ( empty( $idp['certs'] ) ) {
			$this->fail( __( 'Identity provider certificates are not available: login is temporarily not possible.', 'auth-spid-cie' ), 503 );
		}

		$service = $idp['type'];
		$default = ( 'cie' === $service ) ? Config::cie_level() : 2;
		$level   = isset( $_GET['level'] ) ? (int) $_GET['level'] : $default;
		$level   = max( 1, min( 3, $level ) );

		$fallback  = home_url( '/' );
		$return_to = isset( $_GET['returnTo'] ) ? wp_validate_redirect( esc_url_raw( wp_unslash( $_GET['returnTo'] ) ), $fallback ) : $fallback;

		list( $sso_url, $binding ) = $this->pick_endpoint( $idp );
		if ( '' === $sso_url ) {
			$this->fail( __( 'SSO endpoint not available for this identity provider.', 'auth-spid-cie' ), 503 );
		}

		try {
			$request = AuthnRequestBuilder::build( $idp_entity_id, $sso_url, $level, $service, 'post' === $binding );

			RequestStore::set( $request['id'], array(
				'idp_entity_id' => $idp_entity_id,
				'service'       => $service,
				'level'         => $request['level'],
				'comparison'    => $request['comparison'],
				'return_to'     => $return_to,
				'created'       => time(),
			) );

			if ( 'redirect' === $binding ) {
				Bindings::send_redirect( $sso_url, $request['xml'], '', $service );
			} else {
				Bindings::send_post( $sso_url, $request['xml'], '' );
			}
		} catch ( \Exception $e ) {
			\AuthSpidCie\Support\Log::write( '[auth-spid-cie] login: ' . $e->getMessage() );
			$this->fail( __( 'Unable to start authentication. Please contact the site administrator.', 'auth-spid-cie' ), 500 );
		}
	}

	private function handle_acs() {
		$this->require_enabled();
		if ( 'POST' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '' ) ) {
			$this->fail( __( 'Method not allowed.', 'auth-spid-cie' ), 405 );
		}
		$saml_response = isset( $_POST['SAMLResponse'] ) ? wp_unslash( $_POST['SAMLResponse'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- l'autenticita' viene dalla firma SAML; base64 validato dal parser
		if ( ! is_string( $saml_response ) || '' === $saml_response ) {
			$this->fail( __( 'SAML response missing.', 'auth-spid-cie' ) );
		}

		// Locate the pending request through InResponseTo (single use).
		$in_response_to = ResponseValidator::peek_in_response_to( $saml_response );
		if ( '' === $in_response_to || 0 !== strpos( $in_response_to, 'authspidcie_' ) ) {
			$this->fail( __( 'The response cannot be matched to any request.', 'auth-spid-cie' ) );
		}
		$state = RequestStore::consume( $in_response_to );
		if ( ! $state ) {
			$this->fail( __( 'Login request expired or already used. Please try again.', 'auth-spid-cie' ) );
		}

		$idp = IdpRepository::find_by_entity_id( $state['idp_entity_id'] );
		if ( ! $idp || empty( $idp['certs'] ) ) {
			$this->fail( __( 'Identity provider not recognized.', 'auth-spid-cie' ) );
		}

		try {
			$result = ResponseValidator::validate( $saml_response, array(
				'request_id'          => $in_response_to,
				'idp_entity_id'       => $idp['entity_id'],
				'certs'               => $idp['certs'],
				'sp_entity_id'        => Config::entity_id( $state['service'] ),
				'acs_url'             => Config::acs_url(),
				'level'               => $state['level'],
				'comparison'          => $state['comparison'],
				'service'             => $state['service'],
				'required_attributes' => Config::required_attributes( $state['service'] ),
			) );

			$valid_until = $result['not_on_or_after'];
			if ( ! ReplayCache::mark( 'a:' . $result['assertion_id'], $valid_until ) || ! ReplayCache::mark( 'r:' . $result['response_id'], $valid_until ) ) {
				throw new ValidationException( 'Message already used (replay).', 'replay' );
			}

			SessionGate::login( $result['attributes'], array(
				'idp'           => $idp['entity_id'],
				'service'       => $state['service'],
				'name_id'       => $result['name_id'],
				'session_index' => $result['session_index'],
				'authn_class'   => $result['authn_class_ref'],
			) );

			do_action( 'authspidcie_authenticated', $result['attributes'], null, $idp['entity_id'] );

			wp_safe_redirect( ! empty( $state['return_to'] ) ? $state['return_to'] : home_url( '/' ) );
			exit;

		} catch ( ValidationException $e ) {
			\AuthSpidCie\Support\Log::write( sprintf( '[auth-spid-cie] ACS rejected (%s): %s %s', $e->reason, $e->getMessage(), wp_json_encode( $e->details ) ) );
			$this->fail( $this->user_message( $e ) );
		} catch ( \Exception $e ) {
			\AuthSpidCie\Support\Log::write( '[auth-spid-cie] ACS error: ' . $e->getMessage() );
			$this->fail( __( 'Error during authentication. Please try again.', 'auth-spid-cie' ), 500 );
		}
	}

	/** User-safe message. Technical detail goes to the log only. */
	private function user_message( ValidationException $e ) {
		if ( 'idp_error' === $e->reason ) {
			$messages = array(
				'nr19' => __( 'Authentication failed after repeated submission of wrong credentials.', 'auth-spid-cie' ),
				'nr20' => __( 'No credentials compatible with the level required by the service are available.', 'auth-spid-cie' ),
				'nr21' => __( 'Timeout during authentication.', 'auth-spid-cie' ),
				'nr22' => __( 'Consent to send the data was not given.', 'auth-spid-cie' ),
				'nr23' => __( 'Identity suspended or revoked, or credentials blocked.', 'auth-spid-cie' ),
				'nr25' => __( 'Authentication cancelled.', 'auth-spid-cie' ),
			);
			$text = isset( $e->details['message'] ) ? $e->details['message'] : '';
			if ( preg_match( '/nr(\d{2})/i', $text, $m ) && isset( $messages[ 'nr' . $m[1] ] ) ) {
				return $messages[ 'nr' . $m[1] ];
			}
			return __( 'Authentication failed at the identity provider.', 'auth-spid-cie' );
		}
		if ( 'level' === $e->reason ) {
			return __( 'The security level of the digital identity is not sufficient for this service.', 'auth-spid-cie' );
		}
		if ( 'expired' === $e->reason ) {
			return __( 'The authentication response has expired. Please try again.', 'auth-spid-cie' );
		}
		return __( 'Unable to verify the authentication response. Please try again.', 'auth-spid-cie' );
	}

	private function handle_slo() {
		// Local logout only (LogoutRequest towards the IdP is not implemented yet).
		// A nonce is required: otherwise any page could log citizens out (CSRF).
		$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'authspidcie_logout' ) ) {
			wp_safe_redirect( home_url( '/' ) );
			exit;
		}
		SessionGate::logout();
		$fallback = home_url( '/' );
		$to       = isset( $_GET['returnTo'] ) ? wp_validate_redirect( esc_url_raw( wp_unslash( $_GET['returnTo'] ) ), $fallback ) : $fallback;
		wp_safe_redirect( $to );
		exit;
	}

	private function handle_metadata() {
		$service = 'cie' === get_query_var( 'service' ) ? 'cie' : 'spid';
		try {
			$xml = \AuthSpidCie\Saml\MetadataBuilder::generate( $service );
		} catch ( \Exception $e ) {
			\AuthSpidCie\Support\Log::write( '[auth-spid-cie] metadata: ' . $e->getMessage() );
			$this->fail( __( 'Metadata not available: generate the Service Provider certificate first.', 'auth-spid-cie' ), 503 );
		}
		header( 'Content-Type: application/samlmetadata+xml; charset=UTF-8' );
		echo $xml; // phpcs:ignore WordPress.Security.EscapeOutput -- XML document.
		exit;
	}
}
