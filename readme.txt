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
* Ready-made buttons: `[spid_button]`, `[cie_button]`, `[authspidcie_login]` and a dedicated login page.
* Certificate generation or import from the admin panel, with an OpenSSL capability check.
* No Composer, no bundled third-party libraries.

Status: version 0.1.0 is validated locally with the AgID tools (spid-sp-test, spid-saml-check). It has not yet been tested with real identity providers and is not certified.

= External services =

This plugin connects to the following services. No personal data of your visitors is sent by the site's server in the requests marked "server"; the requests marked "browser" are the SAML login itself.

* SPID registry, https://registry.spid.gov.it (server): the site downloads the official list of SPID identity providers with their metadata (cached for 12 hours). The standard WordPress request is sent, which includes the address of your site in the user agent. Operated by AgID (Agenzia per l'Italia Digitale).
* CIE identity provider metadata, https://idserver.servizicie.interno.gov.it, or in test mode https://preproduzione.idserver.servizicie.interno.gov.it (server): the site downloads the metadata of the CIE identity provider. Operated by the Italian Ministry of the Interior.
* SPID and CIE identity providers (browser): when a visitor chooses an identity provider, their browser is redirected to it with a signed SAML request, and comes back with the signed response. What the provider processes is covered by its own privacy policy.
* SPID Demo test identity provider, https://demo.spid.gov.it (server), and optionally https://validator.spid.gov.it: while the plugin is NOT in production mode, the site downloads the metadata of the SPID Demo test identity provider, which appears in the login list marked "test". Switching on "Production environment" in the settings stops this. The administrator can also add other test identity provider addresses.

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

In the WordPress database (network options, autoload off), not in files: updating, reinstalling or redeploying the plugin never loses them, and nothing sensitive sits in the plugin folder. Database backups contain the private key. To store it encrypted, define `AUTHSPIDCIE_SECRET` (a long random string) in wp-config.php: the key is then encrypted with libsodium. If that constant is lost the key cannot be read and a new certificate must be generated and registered again with AgID/CIE.

= What happens to the certificate when I delete the plugin? =

It is kept, together with the registered metadata and the organization settings, because registering again with AgID/CIE is costly. Sessions and caches are removed. Define `AUTHSPIDCIE_REMOVE_DATA_ON_UNINSTALL` as true in wp-config.php to delete everything on uninstall.

= Which PHP version is required? =

PHP 8.0 or later, with the openssl, dom, libxml and mbstring extensions.

== Screenshots ==

1. Login page on a public-administration site, with the SPID and CIE buttons.
2. Admin panel: guided checklist with the next step, and the status of SPID and CIE.
3. Admin panel: organization data, with required fields marked and values suggested from the site.

== Privacy and security ==

* The plugin does not create WordPress users and does not use PHP sessions. A random cookie points to the SPID/CIE attributes (name, tax code...) kept server-side for a limited time (default 2 hours) and deleted at logout.
* The tax code and other attributes are not stored permanently by the plugin; your site decides what to do with them.
* The private key is stored in the database, optionally encrypted with libsodium (`AUTHSPIDCIE_SECRET`).

== Changelog ==

= 0.1.0 =
* First development release.

== Upgrade Notice ==

= 0.1.0 =
First development release.
