# Istruzioni per la prossima AI — auth-spid-cie

Contesto: plugin WordPress **autonomo** (niente Composer, niente librerie) per accesso **SPID e CIE** a servizi pubblici riservati ai cittadini (senza account WP). Leggi **prima** `ANALISI_E_ISTRUZIONI.md`: §0 (decisioni vincolanti), §4 (regole SPID/CIE), §5.7 (tema ASL) e soprattutto **§12 (stato reale e regole)**. Questo file dice solo **cosa fare ora**.

## Regole non negoziabili

1. Lavora solo in `wp-content/plugins/auth-spid-cie/`. `inspirations/` è sola lettura e **non va mai copiata** nel plugin.
2. Zero dipendenze: niente Composer, `vendor/`, npm a runtime, né download di codice. Solo PHP ≥ 8.0 con `openssl`, `dom`, `mbstring` e API WordPress.
3. **Non toccare la logica di sicurezza in `includes/Xml/` e `includes/Saml/ResponseValidator.php`** se non per aggiungere controlli. Mai leggere dati da nodi non coperti dalla firma verificata; mai XPath con valori da input; stringhe dinamiche in XML solo via `XmlSecurity::text_element()` o `setAttribute`.
4. Ogni nuova regola di validazione: **prima un test negativo** in `tests/run.php`, poi il codice. I test devono restare tutti verdi.
5. Output sempre escapato (`esc_*`), input sanitizzato, `manage_options` + nonce su ogni azione admin, guard `ABSPATH` in ogni file.
6. Se una regola SPID/CIE non è chiara, **non indovinare**: implementa il comportamento di `spid-cie-php`, rendilo configurabile e annotalo in `docs/TODO-validator.md`.
7. Non dichiarare "fatto" ciò che non hai eseguito. Alla fine di ogni compito scrivi cosa hai testato (e come) e cosa no.

## Come testare

```bash
php tests/run.php && php tests/run_wp.php
# senza PHP locale (Docker; la cartella deve stare sotto un path condiviso con Docker):
docker run --rm -v "$PWD":/app -w /app php:8.3-cli sh -c 'php tests/run.php; php tests/run_wp.php'
# lint:
docker run --rm -v "$PWD":/app -w /app php:8.3-cli sh -c 'for f in $(find . -name "*.php" -not -path "./inspirations/*"); do php -l $f | grep -v "^No syntax"; done'
```
Stato attuale: 31 + 24 test verdi (PHP 8.0, 8.3, 8.5). Per i test che toccano WordPress estendi gli stub in `tests/run_wp.php`.

## Compiti, in ordine (uno alla volta, consegna e riepilogo a ognuno)

### 1. Pagina impostazioni (admin)
File: `includes/Settings/AdminPage.php` (+ registrazione in `Plugin.php`). Settings API, `manage_options`, `sanitize_callback` su tutto, opzione `wpspid_options` (+ `wpspid_production`). Tab:
- **Generale**: abilita SPID/CIE, produzione/test, mostra Validator, livello CIE (1–3, default **2**), `destination_mode` (`entity_id`|`sso_url`), pagina di ritorno post login/logout.
- **Ente**: `entity_id` (deve iniziare con `https://`), tipo **pubblico/privato**, dati organizzazione, `acs_index`, attributi richiesti (default in `Support/Config`), contatti; per **pubblico**: codice IPA; per **privato**: P.IVA/CF + blocco `fpa:` (§4.5); dati CIE (`NACE2Code`, comune, provincia…).
- **Certificati** (SPID e CIE separati): stato/scadenza, **genera**, **importa chiave+certificato esistenti** (obbligatorio: va mantenuto l'entityID/certificato già registrati), scarica `.crt`. Nonce su ogni azione. Mai mostrare la chiave privata.
- **Stato**: requisiti PHP, orologio, permessi cartella chiavi, ultima cache registry/CIE con pulsante refresh, link ai metadata (`?wpspid=metadata&service=spid|cie`).
- Test unit per la sanitizzazione (entityID non https rifiutato, livello fuori range, ecc.).

### 2. Metadata completo e certificato conformi
- `MetadataBuilder`: `ContactPerson` con estensioni (§4.5): SPID pubblico (`spid:IPACode` + `spid:Public`), privato (`spid:VATNumber`/`FiscalCode` + `spid:Private` + secondo `ContactPerson billing` con `fpa:`), CIE (`cie:*`); `Organization` con dati reali (non `get_bloginfo`); niente `mailto:`; namespace `spid`/`fpa`/`cie` dichiarati solo se usati. Riferimento: `inspirations/spid-cie-php/setup/simplesamlphp/simplesamlphp/lib/SimpleSAML/Metadata/SAMLBuilder.php` ~righe 820-900 e `setup/config/authsources_*_*.tpl`.
- `CertificateManager::generate`: subject secondo Avviso SPID n.29 v.3 (§4.7; ricava i campi da `inspirations/spid-cie-php/setup/Setup.php`, sezione generazione certificato). Annota in `docs/TODO-validator.md` ciò che non puoi verificare.
- Test: metadata valido e firmato per i tre casi (SPID pubblico, SPID privato, CIE); verifica presenza degli elementi chiave via XPath.

### 3. UI con lo stile del tema ASL (§5.7)
- Shortcode `[spid_button]`, `[cie_button]`, pagina/sezione di scelta IdP: elenco da `IdpRepository`, **ordine casuale**, link "Maggiori informazioni / Non hai SPID? / Serve aiuto?", dicitura "Entra con SPID". Markup con classi **Bootstrap Italia** del tema, variabili `--asl-link`/`--asl-link-hover`, loghi `wp-pa-theme/assets/images/identity/spid-bianco.svg` e `cie-bianco.svg`. Niente jQuery/CSS AgID se il tema ha già Bootstrap Italia (opzione "stile AgID standard" come alternativa). Asset con `wp_enqueue_*` e `plugins_url()`; tutto escapato.
- Aggancio al filtro **`dci_area_personale`** (definito in `wp-content/themes/wp-pa-theme/inc/header-footer.php:65`): `url` = pagina di login del plugin; da autenticato mostra nome/cognome + logout (`wpspid_logout_url()`).
- **Leggi per intero** `wp-content/themes/wp-pa-theme/template-parts/prenotazione/tabs.php` e verifica che `$_SESSION['govauth_user_data']` abbia le chiavi attese dal tema (oggi il plugin salva l'array degli attributi SAML con `fiscalNumber` senza `TINIT-`). Adatta il plugin, non il tema, e documentalo.
- Verifica visiva con il tema `wp-pa-theme-asl` attivo.

### 4. Logout completo (SLO) — §4.4
`LogoutRequest` firmata verso l'IdP (`NameID` = entityID IdP, `SessionIndex` e IdP dalla sessione `SessionGate::meta()`), endpoint SLO che riceve `LogoutResponse` e `LogoutRequest` dall'IdP **verificandone la firma** (Redirect: firma sulla query string raw), poi logout locale. Se l'IdP non ha SLO → solo locale. Test su firma e verifica.

### 5. Hardening residuo
- **Login CSRF** (§12.4 punto 6): cookie di binding `SameSite=None; Secure` (solo HTTPS) impostato al login e verificato all'ACS, con fallback documentato su HTTP.
- Rate limit sulla rotta `login` (transient per IP) e limite sui transient pendenti.
- WP-Cron per refresh di registry SPID e metadata CIE; fix o fallback per l'URL CIE di pre-produzione (oggi 404, vedi `docs/TODO-validator.md` punto 6).
- `readme.txt`, `languages/`, documentazione utente in `docs/` (installazione, registrazione metadata AgID/CIE, troubleshooting), script o regola di pacchettizzazione che **esclude** `inspirations/`, `tests/`, `ISTRUZIONI_*`, `ANALISI_*`.

## Fuori scope (non farlo)
eIDAS, modalità proxy/JWT di spid-php, login con creazione utenti WP (resta solo un hook `wpspid_authenticated`), multisite, assertion cifrate.

## Formato della consegna
Per ogni compito: elenco dei file toccati, comandi di test eseguiti con esito reale, punti incerti aggiunti a `docs/TODO-validator.md`, e aggiornamento di `ANALISI_E_ISTRUZIONI.md` §12.3/§12.4 (sposta le voci completate).
