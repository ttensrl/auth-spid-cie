<?php
namespace AuthSpidCie\Ui;

use AuthSpidCie\Idp\IdpRepository;
use AuthSpidCie\Support\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pulsanti "Entra con SPID" / "Entra con CIE", scelta dell'identity provider e riquadro dell'utente
 * collegato. Markup senza JavaScript (details/summary), stili che ereditano i colori del tema.
 *
 * Linee guida SPID: elenco dei gestori in ordine casuale, link "Maggiori informazioni", "Non hai
 * SPID?" e "Serve aiuto?". Il logo CIE non e' incluso (nessuna licenza dichiarata): lo fornisce il
 * tema con il filtro `authspidcie_logo_url`.
 */
class Buttons {

	const URL_INFO    = 'https://www.spid.gov.it';
	const URL_REQUEST = 'https://www.spid.gov.it/richiedi-spid';
	const URL_HELP    = 'https://www.spid.gov.it/serve-aiuto';

	/** Accoda il foglio di stile (solo quando si disegna qualcosa). */
	public static function enqueue() {
		if ( function_exists( 'wp_enqueue_style' ) ) {
			wp_enqueue_style( 'authspidcie-ui', AUTHSPIDCIE_PLUGIN_URL . 'assets/css/authspidcie.css', array(), defined( 'AUTHSPIDCIE_VERSION' ) ? AUTHSPIDCIE_VERSION : '1' );
		}
	}

	/**
	 * URL del logo di un servizio ('spid'|'cie'). Il CIE e' vuoto di default.
	 *
	 * @param string $service
	 * @return string
	 */
	public static function logo( $service ) {
		$default = 'spid' === $service ? AUTHSPIDCIE_PLUGIN_URL . 'assets/img/spid-logo-bianco.svg' : '';
		return (string) apply_filters( 'authspidcie_logo_url', $default, $service );
	}

	private static function login_url( $entity_id, $level, $return_to ) {
		$args = array( 'authspidcie' => 'login', 'idp' => $entity_id, 'level' => max( 1, min( 3, (int) $level ) ) );
		if ( $return_to ) {
			$args['returnTo'] = $return_to;
		}
		return add_query_arg( $args, home_url( '/' ) );
	}

	/** Nome da mostrare: alcuni gestori hanno nel registro un URL al posto del nome. */
	private static function label( array $idp ) {
		$d = isset( $idp['display_name'] ) ? trim( $idp['display_name'] ) : '';
		return ( '' === $d || preg_match( '#^https?://#i', $d ) ) ? $idp['name'] : $d;
	}

	/**
	 * Logo del gestore, solo da file inclusi nel plugin (nessuna richiesta a CDN esterni):
	 * il registro AgID indica un URL, ne usiamo solo il nome file se esiste in assets/img/idp/.
	 *
	 * @return string URL del logo o stringa vuota.
	 */
	private static function idp_logo( array $idp ) {
		$file = isset( $idp['logo'] ) ? sanitize_file_name( wp_basename( (string) wp_parse_url( $idp['logo'], PHP_URL_PATH ) ) ) : '';
		if ( ! preg_match( '/^spid-idp-[a-z0-9-]+\.svg$/', $file ) || ! file_exists( AUTHSPIDCIE_PLUGIN_DIR . 'assets/img/idp/' . $file ) ) {
			return '';
		}
		return AUTHSPIDCIE_PLUGIN_URL . 'assets/img/idp/' . $file;
	}

	private static function usable( array $idp ) {
		return ! empty( $idp['certs'] ) && ! empty( $idp['sso'] );
	}

	private static function img( $service ) {
		$url = self::logo( $service );
		return '' === $url ? '' : '<img class="authspidcie__logo" src="' . esc_url( $url ) . '" alt="" height="28" />';
	}

	/**
	 * Pulsante SPID con l'elenco dei gestori.
	 *
	 * @param array $args {open:bool, level:int, return:string}
	 * @return string HTML, vuoto se SPID non e' attivo.
	 */
	public static function spid_button( array $args = array() ) {
		if ( ! Config::is_enabled() || ! Config::get( 'spid_enabled', true ) ) {
			return '';
		}
		$args  = $args + array( 'open' => false, 'level' => 2, 'return' => '' );
		$idps  = IdpRepository::get_all();
		$idps  = array_values( array_filter( $idps, function ( $i ) { return 'spid' === $i['type']; } ) );
		shuffle( $idps ); // Ordine casuale, come richiesto dalle linee guida.
		self::enqueue();

		$items = '';
		foreach ( $idps as $idp ) {
			$name = self::label( $idp );
			$logo = self::idp_logo( $idp );
			$face = '' !== $logo ? '<img class="authspidcie__idp-logo" src="' . esc_url( $logo ) . '" alt="' . esc_attr( $name ) . '" loading="lazy" />' : esc_html( $name );
			if ( self::usable( $idp ) ) {
				$items .= '<li><a href="' . esc_url( self::login_url( $idp['entity_id'], $args['level'], $args['return'] ) ) . '" rel="nofollow">' . $face . '</a></li>';
			} else {
				$items .= '<li><span class="authspidcie__idp-off" aria-disabled="true">' . esc_html( $name ) . ' <small>(' . esc_html__( 'not available', 'auth-spid-cie' ) . ')</small></span></li>';
			}
		}

		return '<div class="authspidcie authspidcie--spid"><details' . ( $args['open'] ? ' open' : '' ) . ' class="authspidcie__menu">'
			. '<summary class="authspidcie__btn">' . self::img( 'spid' ) . '<span>' . esc_html__( 'Log in with SPID', 'auth-spid-cie' ) . '</span></summary>'
			. '<div class="authspidcie__panel"><p class="authspidcie__lead">' . esc_html__( 'Choose your SPID identity provider', 'auth-spid-cie' ) . '</p>'
			. '<ul class="authspidcie__idps">' . $items . '</ul>'
			. '<p class="authspidcie__help"><a href="' . esc_url( self::URL_INFO ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'More information about SPID', 'auth-spid-cie' ) . '</a>'
			. ' &middot; <a href="' . esc_url( self::URL_REQUEST ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Don\'t have SPID?', 'auth-spid-cie' ) . '</a>'
			. ' &middot; <a href="' . esc_url( self::URL_HELP ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Need help?', 'auth-spid-cie' ) . '</a></p>'
			. '</div></details></div>';
	}

	/**
	 * Pulsante CIE. Senza certificati dell'IdP (es. pre-produzione non raggiungibile) e' disattivato.
	 *
	 * @param array $args {level:int, return:string}
	 * @return string HTML, vuoto se la CIE non e' attiva.
	 */
	public static function cie_button( array $args = array() ) {
		if ( ! Config::is_enabled() || ! Config::get( 'cie_enabled', true ) ) {
			return '';
		}
		$args = $args + array( 'level' => Config::cie_level(), 'return' => '' );
		$idps = IdpRepository::get_cie_idps();
		$idp  = $idps ? $idps[0] : array();
		self::enqueue();

		$label = '<span>' . esc_html__( 'Log in with CIE', 'auth-spid-cie' ) . '</span>';
		if ( $idp && self::usable( $idp ) ) {
			return '<div class="authspidcie authspidcie--cie"><a class="authspidcie__btn" href="' . esc_url( self::login_url( $idp['entity_id'], $args['level'], $args['return'] ) ) . '" rel="nofollow">' . self::img( 'cie' ) . $label . '</a></div>';
		}
		return '<div class="authspidcie authspidcie--cie"><span class="authspidcie__btn authspidcie__btn--off" role="link" aria-disabled="true">' . self::img( 'cie' ) . $label . '</span>'
			. '<p class="authspidcie__note">' . esc_html__( 'Login with CIE is temporarily unavailable.', 'auth-spid-cie' ) . '</p></div>';
	}

	/**
	 * Riquadro "accesso effettuato" con il logout. Il nome arriva da attributi SAML: sempre escapato.
	 *
	 * @param array  $attrs      Attributi SAML.
	 * @param string $logout_url
	 * @return string
	 */
	public static function user_box( array $attrs, $logout_url ) {
		$name = trim( ( isset( $attrs['name'] ) ? $attrs['name'] : '' ) . ' ' . ( isset( $attrs['familyName'] ) ? $attrs['familyName'] : '' ) );
		if ( '' === $name ) {
			return '';
		}
		self::enqueue();
		return '<div class="authspidcie authspidcie--user"><p>' . esc_html__( 'You are logged in as', 'auth-spid-cie' ) . ' <strong>' . esc_html( $name ) . '</strong>.</p>'
			. '<a class="authspidcie__btn authspidcie__btn--ghost" href="' . esc_url( $logout_url ) . '">' . esc_html__( 'Log out', 'auth-spid-cie' ) . '</a></div>';
	}

	/**
	 * Pagina di accesso completa (usata dalla rotta ?authspidcie=choose e dallo shortcode [authspidcie_login]).
	 *
	 * @param array $args {return:string}
	 * @return string
	 */
	public static function page( array $args = array() ) {
		if ( ! Config::is_enabled() ) {
			return '';
		}
		self::enqueue();
		$args = $args + array( 'return' => '' );

		$body = '';
		if ( function_exists( 'authspidcie_is_authenticated' ) && authspidcie_is_authenticated() ) {
			$body .= self::user_box( authspidcie_get_attributes(), authspidcie_logout_url( $args['return'] ) );
		} else {
			$body .= self::spid_button( array( 'open' => true, 'return' => $args['return'] ) ) . self::cie_button( array( 'return' => $args['return'] ) );
		}
		return '<section class="authspidcie-page"><div class="authspidcie-page__box"><h1 class="authspidcie-page__title">' . esc_html__( 'Log in with SPID or CIE', 'auth-spid-cie' ) . '</h1>'
			. '<p class="authspidcie-page__intro">' . esc_html__( 'Use your digital identity to access online services. We do not ask you to create an account: we will only use the data needed to identify you.', 'auth-spid-cie' ) . '</p>'
			. $body . '</div></section>';
	}
}
