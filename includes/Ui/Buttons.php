<?php
namespace WpSpidCie\Ui;

use WpSpidCie\Idp\IdpRepository;
use WpSpidCie\Support\Config;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Pulsanti "Entra con SPID" / "Entra con CIE", scelta dell'identity provider e riquadro dell'utente
 * collegato. Markup senza JavaScript (details/summary), stili che ereditano i colori del tema.
 *
 * Linee guida SPID: elenco dei gestori in ordine casuale, link "Maggiori informazioni", "Non hai
 * SPID?" e "Serve aiuto?". Il logo CIE non e' incluso (nessuna licenza dichiarata): lo fornisce il
 * tema con il filtro `wpspid_logo_url`.
 */
class Buttons {

	const URL_INFO    = 'https://www.spid.gov.it';
	const URL_REQUEST = 'https://www.spid.gov.it/richiedi-spid';
	const URL_HELP    = 'https://www.spid.gov.it/serve-aiuto';

	/** Accoda il foglio di stile (solo quando si disegna qualcosa). */
	public static function enqueue() {
		if ( function_exists( 'wp_enqueue_style' ) ) {
			wp_enqueue_style( 'wpspid-ui', WPSPID_PLUGIN_URL . 'assets/css/wpspid.css', array(), defined( 'WPSPID_VERSION' ) ? WPSPID_VERSION : '1' );
		}
	}

	/**
	 * URL del logo di un servizio ('spid'|'cie'). Il CIE e' vuoto di default.
	 *
	 * @param string $service
	 * @return string
	 */
	public static function logo( $service ) {
		$default = 'spid' === $service ? WPSPID_PLUGIN_URL . 'assets/img/spid-logo-bianco.svg' : '';
		return (string) apply_filters( 'wpspid_logo_url', $default, $service );
	}

	private static function login_url( $entity_id, $level, $return_to ) {
		$args = array( 'wpspid' => 'login', 'idp' => $entity_id, 'level' => max( 1, min( 3, (int) $level ) ) );
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

	private static function usable( array $idp ) {
		return ! empty( $idp['certs'] ) && ! empty( $idp['sso'] );
	}

	private static function img( $service ) {
		$url = self::logo( $service );
		return '' === $url ? '' : '<img class="wpspid__logo" src="' . esc_url( $url ) . '" alt="" height="28" />';
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
			if ( self::usable( $idp ) ) {
				$items .= '<li><a href="' . esc_url( self::login_url( $idp['entity_id'], $args['level'], $args['return'] ) ) . '" rel="nofollow">' . esc_html( $name ) . '</a></li>';
			} else {
				$items .= '<li><span class="wpspid__idp-off" aria-disabled="true">' . esc_html( $name ) . ' <small>(non disponibile)</small></span></li>';
			}
		}

		return '<div class="wpspid wpspid--spid"><details' . ( $args['open'] ? ' open' : '' ) . ' class="wpspid__menu">'
			. '<summary class="wpspid__btn">' . self::img( 'spid' ) . '<span>' . esc_html__( 'Entra con SPID', 'wp-spid-cie' ) . '</span></summary>'
			. '<div class="wpspid__panel"><p class="wpspid__lead">' . esc_html__( 'Scegli il tuo gestore di identità SPID', 'wp-spid-cie' ) . '</p>'
			. '<ul class="wpspid__idps">' . $items . '</ul>'
			. '<p class="wpspid__help"><a href="' . esc_url( self::URL_INFO ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Maggiori informazioni su SPID', 'wp-spid-cie' ) . '</a>'
			. ' &middot; <a href="' . esc_url( self::URL_REQUEST ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Non hai SPID?', 'wp-spid-cie' ) . '</a>'
			. ' &middot; <a href="' . esc_url( self::URL_HELP ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Serve aiuto?', 'wp-spid-cie' ) . '</a></p>'
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

		$label = '<span>' . esc_html__( 'Entra con CIE', 'wp-spid-cie' ) . '</span>';
		if ( $idp && self::usable( $idp ) ) {
			return '<div class="wpspid wpspid--cie"><a class="wpspid__btn" href="' . esc_url( self::login_url( $idp['entity_id'], $args['level'], $args['return'] ) ) . '" rel="nofollow">' . self::img( 'cie' ) . $label . '</a></div>';
		}
		return '<div class="wpspid wpspid--cie"><span class="wpspid__btn wpspid__btn--off" role="link" aria-disabled="true">' . self::img( 'cie' ) . $label . '</span>'
			. '<p class="wpspid__note">' . esc_html__( 'Accesso con CIE temporaneamente non disponibile.', 'wp-spid-cie' ) . '</p></div>';
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
		return '<div class="wpspid wpspid--user"><p>' . esc_html__( 'Hai effettuato l\'accesso come', 'wp-spid-cie' ) . ' <strong>' . esc_html( $name ) . '</strong>.</p>'
			. '<a class="wpspid__btn wpspid__btn--ghost" href="' . esc_url( $logout_url ) . '">' . esc_html__( 'Esci', 'wp-spid-cie' ) . '</a></div>';
	}

	/**
	 * Pagina di accesso completa (usata dalla rotta ?wpspid=choose e dallo shortcode [wpspid_login]).
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
		if ( function_exists( 'wpspid_is_authenticated' ) && wpspid_is_authenticated() ) {
			$body .= self::user_box( wpspid_get_attributes(), wpspid_logout_url( $args['return'] ) );
		} else {
			$body .= self::spid_button( array( 'open' => true, 'return' => $args['return'] ) ) . self::cie_button( array( 'return' => $args['return'] ) );
		}
		return '<section class="wpspid-page"><div class="wpspid-page__box"><h1 class="wpspid-page__title">' . esc_html__( 'Accedi con SPID o CIE', 'wp-spid-cie' ) . '</h1>'
			. '<p class="wpspid-page__intro">' . esc_html__( 'Usa la tua identità digitale per accedere ai servizi online. Non ti chiediamo di creare un account: useremo solo i dati necessari per identificarti.', 'wp-spid-cie' ) . '</p>'
			. $body . '</div></section>';
	}
}
