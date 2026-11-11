<?php
/**
 * Configura il plugin per i test:  wp eval-file /work/provision.php
 * Variabili d'ambiente: SP_TYPE=public|private (default public).
 * Dati dell'ente FITTIZI, solo per test locali.
 */
use AuthSpidCie\Cert\CertificateManager;
use AuthSpidCie\Support\Config;

$type    = 'private' === getenv( 'SP_TYPE' ) ? 'private' : 'public';
$idp_xml = file_exists( '/work/.work/fake-idp.xml' ) ? file_get_contents( '/work/.work/fake-idp.xml' ) : '';

$opts = array(
	'_form'            => 1,
	'enabled'          => 1,
	'spid_enabled'     => 1,
	'cie_enabled'      => 1,
	'cie_level'        => 2,
	'entity_id'        => 'https://sp.example.test',
	'sp_type'          => $type,
	'sp_name'          => 'Servizi online',
	'sp_description'   => 'Servizi online ai cittadini',
	'org_name'         => 'Ente di Prova',
	'org_display_name' => 'Ente di Prova',
	'org_url'          => 'https://www.example.test',
	'org_code_type'    => 'public' === $type ? 'IPACode' : 'VATNumber',
	'org_code'         => 'public' === $type ? 'c_h501' : '01234567890',
	'country'          => 'IT',
	'locality'         => 'Roma',
	'contact_email'    => 'info@example.test',
	'contact_phone'    => '+390612345678',
	'fpa_id_paese'     => 'IT',
	'fpa_id_codice'    => '01234567890',
	'fpa_denominazione' => 'Ente di Prova Srl',
	'fpa_indirizzo'    => 'Via Roma',
	'fpa_numero_civico' => '1',
	'fpa_cap'          => '00100',
	'fpa_comune'       => 'Roma',
	'fpa_provincia'    => 'RM',
	'fpa_nazione'      => 'IT',
	'fpa_org_name'     => 'Ente di Prova Srl',
	'fpa_email'        => 'fatture@example.test',
	'fpa_phone'        => '+390612345678',
	'cie_fiscal_code'  => '01234567890',
	'cie_nace2'        => '84.11',
	'cie_municipality' => '058091',
	'cie_province'     => 'RM',
	'attributes'       => array( 'name', 'familyName', 'dateOfBirth', 'fiscalNumber', 'email' ),
	'test_demo'        => 0,
	'test_idp_xml'     => $idp_xml,
);
update_option( 'authspidcie_options', $opts );
update_option( 'authspidcie_options', array_merge( get_option( 'authspidcie_options' ), array() ) );

foreach ( array( 'spid', 'cie' ) as $service ) {
	CertificateManager::generate( $service, array(
		'org_name'       => 'Ente di Prova',
		'common_name'    => 'Ente di Prova',
		'uri'            => 'https://sp.example.test',
		'org_identifier' => Config::organization_identifier(),
		'country'        => 'IT',
		'locality'       => 'Roma',
		'public'         => 'public' === $type,
	), 730 );
}
\AuthSpidCie\Idp\TestIdps::refresh();
WP_CLI::success( "Plugin configurato (ente $type), certificati SPID e CIE generati." );
