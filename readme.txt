=== Auth SPID CIE ===
Contributors: lucaterribili
Tags: spid, cie, saml, authentication, italy
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 0.1.0
License: GPLv3 or later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Login with SPID and CIE (Italian digital identity) as a standalone SAML 2.0 Service Provider, with no external dependencies.

== Description ==

Auth SPID CIE turns your site into a SAML 2.0 Service Provider for the Italian digital identity systems SPID and CIE (Carta d'Identità Elettronica). Visitors authenticate with their identity provider and the site receives only the attributes it needs, without creating a WordPress account.

Features:

* SPID and CIE login with signed AuthnRequests (Redirect and POST bindings).
* Strict validation of SAML Responses: signature, Issuer, Destination, InResponseTo, Audience, timing, replay protection.
* Signed SP metadata for public or private entities.
* Ready-made buttons: `[spid_button]`, `[cie_button]`, `[wpspid_login]` and a dedicated login page.
* Certificate generation or import from the admin panel, with an OpenSSL capability check.
* No Composer, no bundled third-party libraries.

Status: version 0.1.0 is validated locally with the AgID tools (spid-sp-test, spid-saml-check). It has not yet been tested with real identity providers and is not certified.

= External services =

This plugin contacts the following services, only to perform the login you configure:

* SPID registry (https://registry.spid.gov.it): download of the list of identity providers and their metadata. No personal data is sent.
* CIE identity provider (https://idserver.servizicie.interno.gov.it, pre-production: https://preproduzione.idserver.servizicie.interno.gov.it): the visitor's browser is redirected there with a signed SAML AuthnRequest. Provided by the Italian Ministry of the Interior.
* SPID identity providers chosen by the visitor: same redirect flow, with the SAML AuthnRequest.
* Optional test endpoints (demo.spid.gov.it, validator.spid.gov.it) are used only if the administrator configures them for testing.

Privacy policy of each provider applies to the data processed by it.

== Installation ==

1. Upload the plugin to `/wp-content/plugins/auth-spid-cie` or install it from the Plugins screen.
2. Activate it. The plugin checks that OpenSSL works on your server.
3. Go to the plugin settings, fill in your organization data and generate (or import) the certificates.
4. Register the generated metadata with AgID / the CIE federation.
5. Add `[spid_button]` or `[cie_button]` to a page.

== Frequently Asked Questions ==

= Does it create WordPress users? =

No. Citizens get a protected PHP session with their SAML attributes, available to the theme and other plugins.

= Where are the keys stored? =

In the WordPress database (network options, autoload off), not in files: updating, reinstalling or redeploying the plugin never loses them, and nothing sensitive sits in the plugin folder. Database backups contain the private key. To store it encrypted, define `WPSPID_SECRET` (a long random string) in wp-config.php: the key is then encrypted with libsodium. If that constant is lost the key cannot be read and a new certificate must be generated and registered again with AgID/CIE.

= What happens to the certificate when I delete the plugin? =

It is kept, together with the registered metadata and the organization settings, because registering again with AgID/CIE is costly. Sessions and caches are removed. Define `WPSPID_REMOVE_DATA_ON_UNINSTALL` as true in wp-config.php to delete everything on uninstall.

= Which PHP version is required? =

PHP 8.0 or later, with the openssl, dom, libxml and mbstring extensions.

== Screenshots ==

1. Login page on a public-administration site, with the SPID and CIE buttons.
2. Admin panel: status, requirements check and registered-metadata snapshot.
3. Admin panel: organization data for the SAML metadata.

== Privacy and security ==

* The plugin does not create WordPress users and does not use PHP sessions. A random cookie points to the SPID/CIE attributes (name, tax code...) kept server-side for a limited time (default 2 hours) and deleted at logout.
* The tax code and other attributes are not stored permanently by the plugin; your site decides what to do with them.
* The private key is stored in the database, optionally encrypted with libsodium (`WPSPID_SECRET`).

== Changelog ==

= 0.1.0 =
* First development release.

== Upgrade Notice ==

= 0.1.0 =
First development release.
