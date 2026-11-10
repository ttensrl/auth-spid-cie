# wp-spid-cie — Analisi e istruzioni di sviluppo

> Documento destinato a un'altra AI (o sviluppatore) che dovrà implementare il plugin.
> Contiene: obiettivo, analisi dei due progetti in `inspirations/`, cosa va replicato, architettura proposta, piano di lavoro, checklist di sicurezza e test, domande aperte.
> Data analisi: 2026-11-08. Percorso plugin: `wp-content/plugins/wp-spid-cie/`.

---

## 0. Decisioni già prese dal committente (vincolanti, aggiornano il resto del documento)

| Tema | Decisione |
|---|---|
| Uso | SPID/CIE servono per **aree riservate di servizi pubblici** (es. prenotazioni), usate da **cittadini che non hanno un account WordPress**. |
| Modalità | **Gate (B) è la modalità principale e di default**: sessione SPID/CIE senza utente WP. La modalità A (login/creazione utente WP) resta **opzionale e disattivata di default**, utile solo per redattori/dipendenti. |
| Tipo ente | **Pubblico e privato, entrambi, configurabili da admin** (cambiano ContactPerson, certificato, campi richiesti). |
| eIDAS | **Escluso** (architettura predisposta, nessun codice eIDAS). Non serve: è l'accesso con identità digitali di altri Paesi UE. |
| CIE | Livello di default **2**, come nel plugin `wp-auth-gov-proxy`; binding sempre POST; livello configurabile 1–3 in admin. |
| Purpose | Non richiesto: implementarlo come opzione nascosta/avanzata solo se avanza tempo (§4.1). |
| Stile bottoni | **Quello del tema `wp-pa-theme-asl`** (vedi §5.7), non il markup AgID di default dove in conflitto. |
| Compatibilità | Il plugin **sostituisce `wp-auth-gov-proxy`**: deve fornire gli stessi punti di integrazione che il tema già usa (§5.7). |

---

## 1. Obiettivo

Realizzare un **plugin WordPress autonomo** per l'autenticazione **SPID** e **CIE** (Service Provider SAML2) che:

- **non richiede Composer**, né `vendor/`, né SimpleSAMLphp, né librerie esterne scaricate a runtime;
- **non dipende da un'installazione separata di `spid-cie-php`**: ne replica *solo la logica necessaria* in codice nativo del plugin;
- funziona con le sole estensioni PHP standard (`openssl`, `dom`/`libxml`, `mbstring`) e le API di WordPress (`wp_remote_get`, `transient`, `options`, rewrite/REST, ecc.);
- si installa come un normale plugin (zip → attiva → configura da admin → scarica metadata → registra su AgID/CIE).

Il plugin esistente dell'utente (`inspirations/wp-auth-gov-proxy`) è solo un *wrapper* attorno a `spid-cie-php`/SimpleSAMLphp installato a parte. Va considerato **reference funzionale e di UX, non base di codice da estendere**.

---

## 2. Cosa c'è in `inspirations/`

### 2.1 `wp-auth-gov-proxy` (plugin WP dell'utente, ~35 KB)

| File | Ruolo |
|---|---|
| `wp-auth-gov-proxy.php` | Bootstrap plugin: autoloader PSR-4 (`WpAuthGovProxy\`), hook di attivazione che scarica il JSON del registry IdP, pagina impostazioni (Settings API) con 4 opzioni, query var `idp`. |
| `src/classes/WPSpidCie.php` | Classe principale (clone adattato di `SPID_PHP` di spid-php): mappa IdP, `login()`, `logout()`, `getAttributes()`, generazione HTML bottoni SPID/CIE. |
| `src/contracts/AbstractSpid.php` | Interfaccia astratta (copia di `AbstractSPID`). |
| `src/supports/WPDependencyManager.php` | Carica `<library_path>/vendor/autoload.php` (percorso configurato in admin) e verifica con `class_exists` le classi SimpleSAML/SAML2. |
| `src/supports/SimpleWPAuthSAML.php` | Facciata su `SimpleSAML\Auth\Simple`, `Session`, `SAML2\Constants`, `Chunk` (per l'estensione `spid:Purpose`). |
| `src/supports/WPMetadataHandler.php` | Facciata su `MetaDataStorageHandler` di SimpleSAML. |
| `resources/spid-idps.json` | Snapshot del registry AgID (12 IdP SPID). **Utilissimo come fixture di test**: contiene già `entity_id`, `organization_name`, `organization_display_name`, `logo_uri`, `signing_certificate_x509[]`, `single_sign_on_service[]` (binding+location), `single_logout_service[]`, `attribute[]`, `extensions`. → **Non serve scaricare/parsare il metadata XML degli IdP SPID: il JSON del registry basta.** |

Opzioni salvate (`wp_auth_gov_proxy_options`): `wp_auth_gov_spid_enabled`, `wp_auth_gov_library_path`, `wp_auth_gov_production`, `wp_auth_gov_validator_enabled`.

#### Difetti/rischi del plugin esistente da NON ereditare

1. **Dipendenza totale da SimpleSAMLphp esterno** (percorso libreria arbitrario → `require_once` di un path scelto in admin).
2. `isAuthenticated()` **ritorna `true` se il plugin è disabilitato**: semantica pericolosa per un controllo d'accesso. Il nuovo plugin deve ritornare `false`/non applicare gate quando disabilitato, in modo esplicito.
3. Scrive file nella directory del plugin (`resources/spid-idps.json`, e `spid-idps.json` nel *cwd* a ogni render del bottone!) e fa `file_get_contents` su URL remoto **a ogni render** → lento, fragile, non scrivibile su molti hosting. Usare `wp_remote_get` + cache (option/transient/file in `wp-content/uploads/wp-spid-cie/`) + refresh via WP-Cron.
4. Output HTML **non escapato** (`organization_name`, `logo_uri` concatenati in attributi) → XSS; handler `onerror` con virgolette rotte; usare `esc_attr/esc_url/esc_html`.
5. Percorsi hardcoded `/govauth/...` per CSS/JS/immagini dei bottoni; jQuery `$` globale inserito inline; usare `plugins_url()` + `wp_enqueue_script/style`.
6. `insertCIEButton()` ha **`?idp=CIE TEST` hardcoded** ignorando la modalità produzione.
7. `login()` forza CIE a livello 2 (spid-php di default usa 3 e accetta 1/2/3: vedi §4.4).
8. `returnTo` non validato → open redirect. Usare `wp_validate_redirect()` / allow-list host.
9. Nessun nonce/anti-CSRF, nessuna `sanitize_callback` su `register_setting`.
10. Chiave IdP = `organization_name` (stringa fragile) mappata su array hardcoded; usare **`entity_id`** come identificatore.
11. `#TODO FIX` su `setPurpose` (estensione `spid:Purpose`), `#TODO VEDERE SE IL JSON FA LA STESSA COSA` → il JSON del registry sostituisce la mappa hardcoded.
12. Nessuna gestione errori utente, nessun log, nessun uninstall.

### 2.2 `spid-cie-php` (SDK di Michele D'Amico, licenza Apache-2.0)

Non è una libreria runtime: è uno **script Composer di setup** (`setup/Setup.php`, ~100 KB) che:

1. installa SimpleSAMLphp 1.19.9 (+ `web-token/jwt-*`, `symfony/filesystem`) e i pacchetti grafici AgID;
2. **sovrascrive file di SimpleSAMLphp/SAML2 con versioni patchate** (cartella `setup/simplesamlphp/…`): sono le patch "SPID CUSTOM" che implementano le regole tecniche SPID → **questo è il cuore da replicare** (§4);
3. genera certificati X.509 (`spid-sp.crt/pem`, `cie-sp.crt/pem`) con OpenSSL;
4. scarica i metadata IdP (registry SPID, demo, validator, CIE test/prod) e li converte in `saml20-idp-remote.php`;
5. compila i template `authsources_*.tpl` / `config.tpl` con i dati dell'ente;
6. copia nel webroot `spid-php.php` (classe `SPID_PHP`), pagine d'esempio e asset dei bottoni.

File rilevanti da leggere per capire il comportamento atteso:

| File | Cosa contiene |
|---|---|
| `README.md` | API SDK (login, logout, getAttributes, setPurpose…), flusso, URL metadata (`…/metadata.php/spid`, `…/cie`). |
| `setup/sdk/spid-php.tpl` | Classe `SPID_PHP`: costruisce `$config` per `login()`: `AuthnContextClassRef`, `Comparison`, `saml:idp`, `NameIDPolicy=transient`, `AttributeConsumingServiceIndex`, binding scelto, `spid:Purpose`. **HTML dei bottoni SPID (S/M/L/XL, GET/POST)** e CIE. |
| `setup/config/authsources_spid_*.tpl`, `authsources_cie_*.tpl` | **Configurazione SP** (pubblico/privato): campi, attributi richiesti, `ContactPerson`, estensioni `spid:`/`fpa:`/`cie:`. |
| `setup/simplesamlphp/saml2/src/SAML2/Response.php` | Validazioni SPID sulla Response (vedi §4.3). |
| `setup/simplesamlphp/saml2/src/SAML2/Message.php` | ID/InResponseTo/Destination obbligatori; prefisso ID `spid-php`. |
| `setup/simplesamlphp/simplesamlphp/modules/saml/lib/Message.php` | `processResponse` / `processAssertion`: controlli temporali, NameID, SubjectConfirmation, Issuer, attributi. |
| `setup/simplesamlphp/simplesamlphp/modules/saml/lib/Auth/Source/SP.php` | Invio AuthnRequest (Destination, Issuer, binding, ACS index) e LogoutRequest (NameID = entityID IdP). |
| `setup/simplesamlphp/simplesamlphp/lib/SimpleSAML/Metadata/SAMLBuilder.php` (~r.820-900) e `Signer.php` | **Generazione e firma del metadata SP** con estensioni SPID (`spid:IPACode`/`VATNumber`/`FiscalCode`, `spid:Public/Private`, blocco `fpa:` per privati), `ContactPerson`. |
| `setup/simplesamlphp/saml2/src/SAML2/XML/md/ContactPerson.php`, `EntityDescriptor.php` | Namespace `spid:`/`cie:`, `entityType`, rimozione `mailto:`. |
| `setup/metadata/saml20-idp-remote-cie.ptpl` | Metadata IdP CIE (test e prod): endpoint e certificati. |
| `setup/www/assets/*`, `setup/templates/*` | CSS/JS/immagini bottoni (da riprendere dai repo ufficiali, vedi §6.6). |
| `lib/ResponseHandler*.php`, `setup/sdk/proxy*.tpl` | Modalità **proxy** (JWS/JWE verso client esterni): **fuori scope**. |

> `doc/spid-php-tutorial.gif` e `.stg` pesano ~48 MB: **non vanno copiati nel plugin**. Idem l'intera cartella `inspirations/` va esclusa dal pacchetto finale.

---

## 3. Come funziona il flusso (da replicare nativamente)

```
Utente → [Bottone SPID/CIE] → GET /?wpspid=login&idp=<entityID>&level=2&returnTo=…
   plugin: crea AuthnRequest firmata, salva stato (transient, chiave = ID richiesta)
   → redirect (HTTP-Redirect firmato) o auto-POST form (HTTP-POST) verso SSO dell'IdP
IdP autentica → POST SAMLResponse + RelayState → ACS del plugin (/?wpspid=acs)
   plugin: decode, valida firma + regole SPID (§4.3), consuma stato, anti-replay
   → estrae attributi (fiscalNumber, name, familyName, …)
   → [Modalità WP] trova/crea utente WP, wp_set_auth_cookie → redirect a returnTo
   → [Modalità gate] salva sessione SPID (cookie firmato/transient) → redirect
Logout → LogoutRequest firmata verso SLO IdP → LogoutResponse a /?wpspid=slo → logout WP
Metadata SP → GET /?wpspid=metadata&service=spid|cie (XML firmato)
```

SimpleSAMLphp qui fa: sessione, state storage, costruzione/parsing SAML, firma/verifica XMLDSig, metadata IdP, template. Il plugin deve sostituirli con codice proprio (§5).

---

## 4. Requisiti funzionali SPID/CIE da implementare (estratti dal codice patchato)

### 4.1 AuthnRequest (SP → IdP)

- `ID`: stringa che inizia con lettera/underscore, casuale (spid-php usa prefisso `spid-php` + random; **usare un prefisso proprio**, es. `wpspid_` + 32 hex; salvarlo come chiave dello stato).
- `Version="2.0"`, `IssueInstant` UTC (`Y-m-d\TH:i:s\Z`), `ForceAuthn="true"` (obbligatorio per SPID L2/L3; spid-php lo imposta sempre), `IsPassive` assente/false.
- `Destination`: **spid-php imposta `Destination` = entityID dell'IdP** nel documento XML, mentre il trasporto (redirect/POST) va all'URL SSO del binding scelto. Verificare con il validator AgID quale valore accetta oggi (regole tecniche: "URL dell'endpoint SSO"). *Implementare come parametro configurabile e testare col validator.*
- `Issuer`: valore = entityID SP, `Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"`, `NameQualifier` = entityID SP.
- `NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"`.
- `RequestedAuthnContext Comparison="minimum"` (SPID; spid-php) + `AuthnContextClassRef` = `https://www.spid.gov.it/SpidL{1|2|3}`.
- `AttributeConsumingServiceIndex` = indice configurato (stesso del metadata).
- `AssertionConsumerServiceURL`/`ProtocolBinding`: coerenti con il metadata (ACS solo `HTTP-POST`).
- `Extensions` opzionale: `<spid:Purpose xmlns:spid="https://spid.gov.it/saml-extensions">P|LP|PG|PF|PX</spid:Purpose>` (Avviso AgID n.18 v.2, uso professionale/persona giuridica). Nel plugin utente era un TODO irrisolto.
- **Firma obbligatoria**, RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), digest SHA-256.
  - *HTTP-Redirect*: deflate+base64 della richiesta, query `SAMLRequest&RelayState&SigAlg&Signature` (firma sulla stringa raw dei parametri URL-encoded, **non** XMLDSig).
  - *HTTP-POST*: XMLDSig **enveloped** dentro la richiesta (Exclusive C14N, posizione subito dopo `Issuer`), form auto-submit.
- Scelta binding: SPID default Redirect (con opzione POST); **CIE sempre POST** (spid-php forza `post=true` per CIE).

### 4.2 Livelli e comparison

- SPID: livelli 1/2/3; input non valido → 2 (default spid-php).
- CIE: spid-php accetta 1/2/3 con default 3 (nota: Decreto 8/9/2022 ammette CIE a L1/L2); il plugin utente forzava 2. → **Rendere configurabile** (default 2, range 1–3), con avvertenza.
- Comparison inviata: `minimum`. Validare nella Response secondo il comparison richiesto (§4.3).

### 4.3 Validazione della Response (ACS) — checklist obbligatoria

Da `Response.php` / `Message.php` / `modules/saml/lib/Message.php` (blocchi "SPID CUSTOM"):

**Response**
- `ID`, `InResponseTo`, `Destination` presenti e non vuoti; `Version="2.0"`.
- `Destination` == URL ACS corrente (confronto senza query).
- `IssueInstant` non più vecchio di ~60 s (e non nel futuro oltre la tolleranza).
- `Issuer` presente, `Format=…nameid-format:entity`, valore == `entityID` dell'IdP usato nella richiesta.
- `InResponseTo` deve corrispondere a una richiesta pendente (stato salvato) **non ancora consumata** (anti-replay). *spid-php rimuove il controllo di stato in `processResponse` ma lo fa in `Response.php` via `State::loadState`; nel plugin: un solo controllo, rigoroso.*
- Status `Success`; altrimenti mappare gli errori SPID (codici `nr19`–`nr30`, es. "autenticazione fallita", "utente nega consenso", "livello non supportato"…) in messaggi italiani per l'utente.

**Assertion** (solo se Success)
- Deve essere **firmata** (la sola Response firmata NON basta: spid-php ha commentato il fallback). Verificare firma con i certificati `signing_certificate_x509[]` dell'IdP (registry) e algoritmo in allow-list (RSA-SHA256/384/512; **rifiutare SHA-1**).
- `Assertion/Issuer` non vuoto, `Format=entity`, valore == entityID IdP.
- `IssueInstant`: non scaduto (>60 s) né futuro (>60 s).
- `NameID`: non vuoto, `Format=transient`, `NameQualifier` presente.
- `Subject/SubjectConfirmation/SubjectConfirmationData`: presente, con `Recipient` (== ACS), `InResponseTo` (== ID richiesta), `NotOnOrAfter` (non scaduto).
- `Conditions`: presente, con `NotBefore` e `NotOnOrAfter` (tolleranza skew ~180 s, come SimpleSAML), `AudienceRestriction/Audience` == entityID SP.
- `AuthnStatement/AuthnContext/AuthnContextClassRef` ∈ {SpidL1, SpidL2, SpidL3} e coerente col `Comparison` della richiesta:
  `exact` → uguale; `minimum` → livello risposto ≥ richiesto; `maximum` → ≤.
- `AttributeStatement` presente e non vuoto; **tutti gli attributi richiesti nel metadata devono essere presenti** (eccezione eIDAS).
- Rifiutare più Assertion / strutture ambigue (anti **XML Signature Wrapping**: usare solo il nodo effettivamente coperto dalla firma, verificando che l'URI del `Reference` punti all'`ID` dell'elemento consumato).

**Eccezione CIE** (`Response.php` "CIE bypass"): per gli IdP CIE (entityID = `https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO` e `https://preproduzione.idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO`) spid-php **salta i controlli SPID-specifici su Response** (formato Issuer, Conditions, AuthnContextClassRef SPID…) perché la CIE non li rispetta formalmente. Il plugin deve avere un ramo di validazione CIE distinto, mantenendo comunque: firma valida, Issuer/Destination/InResponseTo/Recipient/tempi.

### 4.4 Logout (SLO)

- `LogoutRequest` firmata verso `SingleLogoutService` dell'IdP (preferenza Redirect, fallback POST).
- **Custom SPID**: nella LogoutRequest il valore del `NameID` è impostato all'**entityID dell'IdP** (non al NameID ricevuto); servono `SessionIndex` e `Issuer` (entity format).
- Endpoint SLO nel metadata SP (`SingleLogoutService` Redirect+POST) che riceve `LogoutResponse` (e `LogoutRequest` avviate dall'IdP) → logout locale WP.
- Opzione "logout solo locale" (equivalente `saml_logout=false` di spid-php).
- Se l'IdP non ha endpoint SLO, fare solo logout locale.

### 4.5 Metadata SP (SPID e CIE, due entità/chiavi distinte)

Generare dinamicamente (endpoint pubblico) un `EntityDescriptor` **firmato** (enveloped, ID = `_` + hash, Exclusive C14N, RSA-SHA256, X509 incluso):

- `entityID` configurabile (spid-php lo chiede in setup; deve iniziare con `https://`).
- `SPSSODescriptor`: `AuthnRequestsSigned="true"`, `WantAssertionsSigned="true"`, `protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"`.
- `KeyDescriptor use="signing"` con il certificato SP.
- `SingleLogoutService` (Redirect e POST), `NameIDFormat transient`.
- `AssertionConsumerService` (POST, `index=0`, `isDefault=true`).
- `AttributeConsumingService` con `index`, `ServiceName` (it) e `RequestedAttribute` (NameFormat `attrname-format:basic`) per gli attributi scelti (default spid-php: vedi template authsources).
- `Organization` (`OrganizationName/DisplayName/URL`, lingua `it`).
- **ContactPerson SPID** (Avviso n.29 v.3, `contactType="other"` con namespace `spid:`):
  - **Pubblico**: `spid:IPACode` + `spid:Public`, `entityType="spid:aggregated|aggregator|…"` dove applicabile, `Company`, `EmailAddress`, `TelephoneNumber`.
  - **Privato**: `spid:VATNumber` (o `spid:FiscalCode`) + `spid:Private`, **più** un secondo `ContactPerson contactType="billing"` con blocco `fpa:` (`IdPaese`, `IdCodice`, `Denominazione`, `Sede` con `Indirizzo/NumeroCivico/CAP/Comune/Provincia/Nazione`, `CessionarioCommittente`). Namespace: `spid` = `https://spid.gov.it/saml-extensions`, `fpa` = `https://spid.gov.it/invoicing-extensions`. Riferimento implementativo: `SAMLBuilder.php` righe ~820-900.
  - Nel metadata finale **non** va il prefisso `mailto:` negli `EmailAddress`.
- **ContactPerson CIE** (`contactType="administrative"`, namespace `cie` = `https://www.cartaidentita.interno.gov.it/saml-extensions`): `cie:Private|Public`, `cie:VATNumber`, `cie:FiscalCode`, `cie:NACE2Code`, `cie:Municipality`, `cie:Province`, `cie:Country` (vedi `authsources_cie_private.tpl`). Attributi CIE: `fiscalNumber, name, familyName, dateOfBirth`.
- Dichiarare `xmlns:spid`/`xmlns:cie` sul root quando usati.

### 4.6 Elenco IdP

- **SPID produzione**: `https://registry.spid.gov.it/entities-idp?output=json` (JSON, formato nel file `resources/spid-idps.json`). Alternativa XML: `https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml`. Ignorare record con `_deleted`/`_disabled` veri.
- **Test/validazione SPID**:
  - Demo: `https://demo.spid.gov.it` (metadata `https://demo.spid.gov.it/metadata.xml`)
  - Demo validator mode: `https://demo.spid.gov.it/validator` (metadata `…/validator/metadata.xml`)
  - Validator AgID: `https://validator.spid.gov.it` (metadata `https://validator.spid.gov.it/metadata.xml`)
  Mostrare solo se non in produzione (Demo) / se abilitati in admin (Validator).
- **CIE**: prod `https://idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata`; test `https://preproduzione.idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata`. In spid-php l'entityID usato è l'URL SSO POST (vedi §4.3); endpoint SSO: `…/idp/profile/SAML2/POST/SSO` (e Redirect). Certificati nel `saml20-idp-remote-cie.ptpl` / nel metadata XML (parsare `KeyDescriptor/…/X509Certificate`). Cache e refresh come per SPID.
- (eIDAS: vedi domande aperte, §10.)

### 4.7 Certificati SP

- Chiave RSA ≥ 2048 (meglio 3072), SHA-256, validità ~730 gg (default spid-php), generata con `openssl_pkey_new` + `openssl_csr_new` + `openssl_csr_sign` (self-signed) — **una coppia per SPID e una per CIE**.
- Subject conforme all'Avviso SPID n.29 v.3 (`commonName`, `organizationName`, `organizationIdentifier` es. `PA:IT-<IPA>` o `VATIT-…`, `serialNumber`, `countryName`, `localityName`, `uri`, `entityID` in SAN/`uniformResourceIdentifier` come da avviso): replicare i campi che `Setup.php` chiede (cercare le variabili `openssl.cnf` nella sezione generazione certificato) e **verificare col validator**.
- Rigenerazione da admin (equivalente `composer make-certificate <days>`) con avviso: cambiare certificato richiede ri-registrazione del metadata.
- **Conservazione chiave privata**: preferibilmente fuori dal webroot (path configurabile / costante in `wp-config.php`); fallback in `wp-content/uploads/wp-spid-cie-private/` con `.htaccess` `Require all denied`, `index.php` vuoto e permessi 0600 (e avviso admin per nginx). Mai in option in chiaro non protetta senza avviso. Mai loggare la chiave.

### 4.8 Attributi utente

Attributi SPID standard: `spidCode, name, familyName, placeOfBirth, countyOfBirth, dateOfBirth, gender, companyName, companyFiscalNumber, registeredOffice, fiscalNumber, ivaCode, idCard, mobilePhone, email, address, domicileStreetAddress, domicilePostalCode, domicileMunicipality, domicileProvince, domicileNation, expirationDate, digitalAddress`. Il valore di `fiscalNumber` è prefissato `TINIT-` (rimuovere il prefisso per il codice fiscale pulito, ma conservare l'originale). Il default di spid-php richiede un sottoinsieme (fiscalNumber/name/familyName/dateOfBirth…): lasciare **selezionabili in admin**, perché ogni attributo richiesto nel metadata deve poi essere ricevuto (§4.3).

---

## 5. Architettura proposta del plugin

### 5.1 Struttura file

```
wp-spid-cie/
├─ wp-spid-cie.php              # header plugin, costanti, autoloader PSR-4 minimale, hook attivazione/disattivazione
├─ uninstall.php                # rimuove options, transient, file generati (con conferma opzionale)
├─ readme.txt                   # formato WordPress.org
├─ LICENSE / NOTICE             # attribuzioni (Apache-2.0 spid-cie-php, asset AgID)
├─ includes/                    # namespace WpSpidCie\
│  ├─ Plugin.php                # singleton, registra hook
│  ├─ Settings/                 # Options (get/set + sanitize + defaults), AdminPage (tab: Generale, SPID, CIE, Attributi, Certificati, Stato/Log)
│  ├─ Http/Router.php           # rewrite rules o query var (wpspid=login|acs|slo|metadata), template_redirect
│  ├─ Saml/
│  │  ├─ AuthnRequestBuilder.php
│  │  ├─ ResponseParser.php     # DOM sicuro + estrazione campi
│  │  ├─ ResponseValidator.php  # §4.3 (rami SPID e CIE)
│  │  ├─ LogoutRequestBuilder.php / LogoutResponseHandler.php
│  │  ├─ MetadataBuilder.php    # §4.5 (SPID e CIE)
│  │  ├─ Bindings.php           # redirect (deflate/sign query) e POST (form auto-submit)
│  │  └─ Constants.php
│  ├─ Xml/
│  │  ├─ XmlSecurity.php        # loadXML sicuro (LIBXML_NONET, no DOCTYPE/entità), helper XPath con namespace
│  │  ├─ Signer.php             # XMLDSig enveloped sign (C14N esclusivo via DOMNode::C14N)
│  │  └─ SignatureVerifier.php  # verifica XMLDSig + verifica firma query redirect
│  ├─ Idp/
│  │  ├─ Registry.php           # fetch + cache JSON registry SPID (wp_remote_get, transient/option, cron)
│  │  ├─ CieMetadata.php        # fetch/parse metadata XML CIE test/prod
│  │  └─ IdpRepository.php      # lista IdP uniforme (entity_id, nome, logo, SSO[], SLO[], certs[])
│  ├─ Cert/CertificateManager.php   # generazione/lettura/rigenerazione, storage sicuro
│  ├─ State/RequestStore.php    # transient: ID richiesta → {idp, level, comparison, returnTo, created}; consume-once
│  ├─ State/ReplayCache.php     # ID Response/Assertion già visti (transient con TTL)
│  ├─ Auth/UserProvisioner.php  # mappa SPID/CIE → utente WP (meta `wpspid_fiscal_number`), ruoli, creazione
│  ├─ Auth/SessionGate.php      # modalità "gate" senza utente WP (cookie firmato HMAC + transient)
│  ├─ Ui/ (Buttons.php, Shortcode.php, Block/, LoginForm.php)  # bottoni, [spid_button], integrazione wp-login.php
│  ├─ Support/ (Logger.php, Errors.php (mappa nr19–nr30), Url.php)
│  └─ Api.php                   # funzioni pubbliche per altri plugin/temi (§5.4)
├─ assets/
│  ├─ spid-sp-access-button/    # css, js, img (vendored, vedi §6.6)
│  ├─ cie-graphics/             # svg bottone "Entra con CIE"
│  └─ js/css propri
└─ languages/
```

Namespace e prefissi unici (`WpSpidCie\`, `wpspid_`) per non confliggere col vecchio plugin `wp-auth-gov-proxy` (può essere attivo contemporaneamente durante la migrazione).

### 5.2 Requisiti tecnici

- PHP ≥ 8.0 (ragionevole; il vecchio SDK chiede 8.1), WP ≥ 6.0; estensioni: `openssl`, `dom`, `libxml`, `mbstring`. **`gmp` e `curl` non servono** (HTTP via `wp_remote_get`). Controllare nell'attivazione e mostrare notice admin se mancano.
- Nessun `require` di path esterni; nessun `eval`; nessun download di codice a runtime (solo dati: JSON/XML metadata, con verifica).
- Fuso/orario: tutti i timestamp SAML in UTC; avvisare in admin se l'orologio del server è sfasato (opzione: controllo contro header `Date` del registry).

### 5.3 Punti tecnici critici (nessuna libreria: implementare con cura)

1. **C14N Esclusivo**: `DOMNode::C14N(true /*exclusive*/, false, null, $inclusiveNsPrefixes)` basta per digest e SignedInfo.
2. **Firma XMLDSig**: costruire `ds:Signature` (SignedInfo con `CanonicalizationMethod=exc-c14n`, `SignatureMethod=rsa-sha256`, `Reference URI="#<ID>"` con transforms `enveloped-signature` + `exc-c14n`, `DigestMethod=sha256`), calcolare digest sul nodo **senza** la Signature, firmare il `SignedInfo` canonicalizzato con `openssl_sign(..., OPENSSL_ALGO_SHA256)`, inserire `KeyInfo/X509Data/X509Certificate`.
3. **Verifica XMLDSig** (la parte più delicata):
   - parsare con DOM sicuro; localizzare le `ds:Signature` **tramite XPath ancorato** sul figlio diretto dell'elemento da validare;
   - verificare che `Reference/@URI` == `#` + `@ID` di quell'elemento (e che l'ID sia unico nel documento → anti-wrapping);
   - ricalcolare digest su copia del nodo con Signature rimossa, confrontare con `hash_equals`;
   - canonicalizzare `SignedInfo` e `openssl_verify` con la chiave pubblica ottenuta **dal certificato dell'IdP nel registry**, mai da `KeyInfo` inviato nel messaggio;
   - whitelist algoritmi (canonicalization: exc-c14n (con/senza commenti → accettare solo senza); signature: rsa-sha256/384/512; digest: sha256/384/512); rifiutare SHA-1/MD5.
   - Supportare più certificati per IdP (rotazione): provarli tutti.
4. **Redirect binding**: la firma è su `SAMLRequest=…&RelayState=…&SigAlg=…` con valori **URL-encoded come inviati**; in ricezione (SLO da IdP) verificare sulla query string raw (`$_SERVER['QUERY_STRING']`), non su `$_GET` decodificato.
5. **Assertion cifrate**: SPID e CIE non le cifrano di norma (metadata SP con solo chiave di firma). Se si volesse supportare `EncryptedAssertion` servirà AES-CBC/GCM + RSA-OAEP via `openssl_*`; *fuori scope iniziale*, ma rifiutare esplicitamente (errore chiaro) invece di ignorare.
6. **Stato richieste**: `set_transient('wpspid_req_'.$id, [...], 10*MINUTE_IN_SECONDS)`; in ACS leggere **e cancellare** (consume-once). Con object cache non persistente i transient possono sparire → in tal caso usare tabella dedicata o option con scadenza; documentare. Valutare tabella custom `{$wpdb->prefix}wpspid_requests` per affidabilità e anti-replay.
7. **Cookie/SameSite**: l'ACS riceve un POST cross-site dall'IdP; i cookie WP con `SameSite=Lax` **non** vengono inviati su POST cross-site, quindi **non fare affidamento sul cookie di sessione per correlare** la Response: la correlazione avviene solo via `InResponseTo` → stato server-side. Il cookie di login WP si imposta *dopo* la validazione, nella risposta all'ACS.
8. **Cache pagine**: le rotte `login/acs/slo/metadata` devono inviare `Cache-Control: no-store` e `DONOTCACHEPAGE`; i bottoni non devono dipendere da nonce/state in pagine cacheable (generare la request solo al click sulla rotta `login`).
9. **Rewrite**: preferire query var + `template_redirect` su URL tipo `/spid/login`, `/spid/acs`, `/spid/slo`, `/spid/metadata` con rewrite rules, con `flush_rewrite_rules()` **solo** in attivazione/disattivazione (non a ogni request). Fornire fallback `/?wpspid=…` se i permalink sono "Semplici". L'URL ACS/SLO/entityID/metadata devono essere **stabili** (sono registrati presso AgID): permetterne la personalizzazione ma avvisare in caso di modifica.

### 5.4 API pubblica per temi/altri plugin

Funzioni helper (equivalenti al vecchio `SPID_PHP`/`WPSpidCie`), tutte con prefisso:

- `wpspid_is_authenticated(): bool` (vera sessione SPID/CIE valida; **mai** `true` se plugin disabilitato)
- `wpspid_get_attributes(): array`, `wpspid_get_attribute(string $name): string`
- `wpspid_login_url(string $idp_entity_id, int $level = 2, string $return_to = '', array $opts = []): string`
- `wpspid_logout_url(string $return_to = ''): string`
- `wpspid_render_button(array $args)` / shortcode `[spid_button size="L" level="2"]` / `[cie_button]` / blocco Gutenberg
- Hook: `do_action('wpspid_authenticated', $attributes, $wp_user_or_null, $idp)`, `apply_filters('wpspid_user_login_data', …)`, `apply_filters('wpspid_user_role', …)`, `apply_filters('wpspid_attributes_requested', …)`.

### 5.5 Integrazione utenti WordPress

Due modalità (selezionabile; **default B = gate**, vedi §0):

- **A — Login WordPress**: lookup utente per user meta `wpspid_fiscal_number` (indice univoco logico); se assente → opzioni: *crea utente* (ruolo configurabile, username es. `spid_<hash>`/CF, email da attributo `email` o placeholder) | *collega a utente esistente con login classico (flusso di linking autenticato)* | *rifiuta*. **Non fare auto-link per email** (account takeover: l'email SPID è dichiarata dall'utente e non sempre verificata). Poi `wp_set_current_user` + `wp_set_auth_cookie` + `do_action('wp_login', …)`.
- **B — Gate/area protetta** (come l'uso nel plugin utente con `requireAuth`/`isAuthenticated`): sessione SPID senza utente WP; cookie opaco firmato (HMAC con `wp_salt`) → record server-side con attributi, scadenza, IdP, `SessionIndex`/`NameID` per il logout. Shortcode/blocco "contenuto riservato" e funzione `wpspid_require_auth($level)`.

Il pulsante può anche comparire in `wp-login.php` (`login_form`, `login_message`) con opzione per nascondere il form password.

### 5.6 Pagina impostazioni (Settings API, `manage_options`, nonce, `sanitize_callback` su tutto)

Tab: **Generale** (abilita SPID/CIE, produzione/test, validator, modalità A/B, ruolo default, redirect post login/logout, tolleranza skew) · **Ente / Metadata** (entityID, tipo pubblico/privato, IPACode/VAT/CF, dati organizzazione, contatti, `fpa:` per privati, dati CIE, ACS index, attributi richiesti, Purpose opzionale) · **Certificati** (stato, scadenza, genera/rigenera, download .crt) · **Metadata** (URL metadata SPID e CIE, anteprima, download firmato, link ai validatori) · **IdP** (stato cache registry, ultimo refresh, refresh manuale) · **Stato/Log** (check requisiti: openssl/dom, orologio, permessi cartella chiavi, rewrite OK; ultimi errori di validazione, senza dati personali completi).

### 5.7 Integrazione con il tema `wp-pa-theme` / `wp-pa-theme-asl` (già presente nel repo)

Analisi dei temi in `wp-content/themes/`:

1. **Pulsante "Area personale" nell'header ASL** (`wp-pa-theme-asl/template-parts/header/site-asl.php`, CSS `.dci-asl-areapersonale` in `assets/css/asl.css`): è un link blu (`--asl-link`, h 42px, testo bianco 600 `.875rem`) con a destra i loghi bianchi `spid-bianco.svg` e `cie-bianco.svg` separati da bordo. L'URL arriva dal filtro **`dci_area_personale`** (`wp-pa-theme/inc/header-footer.php:65`), che nel tema ASL cade di default su `wp_login_url()`.
   → Il plugin deve **agganciarsi a `dci_area_personale`** e impostare `url` = rotta di login del plugin (pagina di scelta SPID/CIE), così il pulsante dell'header porta direttamente al login. Quando l'utente è autenticato, mostrare label tipo "Nome Cognome" + link Logout (da definire col tema: ruolo del filtro è solo `url`/`label`).
2. **Stile dei bottoni**: la pagina di scelta IdP e i bottoni del plugin devono usare le **classi Bootstrap Italia già caricate dal tema** (`btn btn-primary`, modale/lista IdP con componenti Bootstrap Italia) e le **variabili CSS del tema ASL** (`--asl-link`, `--asl-link-hover`, `--asl-blue`), con i **loghi SPID/CIE del tema** (`wp-pa-theme/assets/images/identity/spid-bianco.svg`, `cie-bianco.svg`) come fallback; il plugin non deve caricare jQuery/CSS AgID se Bootstrap Italia è già presente (rilevare con `wp_style_is`/filtro e consentire opzione "usa stile AgID standard"). Rispettare comunque i requisiti AgID: dicitura "Entra con SPID", lista IdP in ordine casuale, link "Maggiori informazioni / Non hai SPID? / Serve aiuto?".
3. **Compatibilità con la sessione legacy**: `wp-pa-theme/template-parts/prenotazione/tabs.php` legge **`$_SESSION['govauth_user_data']`** (con `session_start()`) per precompilare i dati utente nelle prenotazioni. Il vecchio plugin popolava quel dato.
   → Il plugin deve **popolare `$_SESSION['govauth_user_data']`** (array di attributi: `fiscalNumber, name, familyName, email, mobilePhone, …`) dopo il login andato a buon fine, **solo come ponte di compatibilità** (opzione "Compatibilità tema legacy", default attiva), e va **rimosso al logout**. Chiavi/formato esatti vanno verificati leggendo come `tabs.php` usa `$user_data` (leggere il resto del file) prima di implementare. Preferibile in seguito **migrare il tema** a `wpspid_get_attributes()` e togliere il `$_SESSION` (WP non usa le sessioni PHP: avviare la sessione solo se già richiesta, `session_status()`, mai prima degli header; documentare che può confliggere con cache di pagina/REST health-check).
4. **Test**: attivare il tema `wp-pa-theme-asl` e verificare header, pagina di login, prenotazione con dati precompilati.

---

## 6. Piano di lavoro (ordine consigliato, un commit/milestone per fase)

1. **Scaffold**: file principale, autoloader, costanti, requisiti, uninstall, i18n (text domain `wp-spid-cie`, stringhe in italiano).
2. **Xml + firma**: `XmlSecurity`, `Signer`, `SignatureVerifier` con **test unitari** (round-trip firma→verifica; vettori negativi: digest alterato, wrapping, SHA-1, Reference errato). Non procedere finché non passano.
3. **Certificate manager** + pagina Certificati.
4. **Registry IdP** (SPID JSON + CIE XML) con cache/cron; usare `resources/spid-idps.json` come fixture offline.
5. **MetadataBuilder** (SPID pubblico, SPID privato, CIE) + endpoint + firma → validare con il **SPID SAML Check/Validator** (`https://validator.spid.gov.it`) e confrontare l'XML prodotto con quello generato da spid-php (stesso input).
6. **AuthnRequest + bindings + RequestStore + router `login`**.
7. **ACS: parser + validator + replay cache** (con unit test su Response di esempio: positive e negative, incl. CIE).
8. **Provisioning utenti / gate** + hook + API pubblica.
9. **Logout/SLO**.
10. **UI**: bottoni SPID (S/M/L/XL, lista IdP randomizzata come da linee guida AgID — il JS lo fa lato client), bottone CIE, shortcode/blocco, `wp-login.php`.
11. **Hardening, docs, readme, pacchettizzazione** (zip senza `inspirations/` né file di sviluppo).

### 6.6 Asset grafici (nessun Composer: vendorizzarli)

Scaricare **una volta, in fase di sviluppo** (non a runtime) e committare nel plugin, mantenendo licenze/attribuzioni:
- `https://github.com/italia/spid-sp-access-button` (CSS/JS/immagini del bottone; `jquery.min.js` incluso: preferire il jQuery di WP con `wp_enqueue_script('jquery')` e adattare lo script inline che usa `$`),
- `https://github.com/italia/cie-graphics` (SVG "Entra con CIE"),
- logo SPID da `https://github.com/italia/spid-graphics`.
I loghi degli IdP vengono dal campo `logo_uri` del registry (CDN jsDelivr): si può usare direttamente o cache-are localmente. Gli stessi asset sono presenti (versioni vecchie) in `inspirations/spid-cie-php/setup/www/assets/` e `.../templates/`.
Rispettare le linee guida grafiche AgID (testo "Entra con SPID", dimensioni, ordine casuale degli IdP, link "Maggiori informazioni / Non hai SPID? / Serve aiuto?" come nel markup di `addSPIDButtonListItems`).

---

## 7. Sicurezza — checklist non negoziabile

- XML: caricare **sempre** con `LIBXML_NONET`, senza `LIBXML_NOENT`/`LIBXML_DTDLOAD`; rifiutare documenti con `DOCTYPE`; limite dimensione POST SAMLResponse (es. 512 KB); `libxml_use_internal_errors(true)`.
- Firma: solo certificati noti (registry/metadata IdP), whitelist algoritmi, `hash_equals`, anti-wrapping (§5.3), niente fiducia in `KeyInfo` del messaggio.
- Anti-replay: stato consumato una sola volta + cache di `Response/@ID` e `Assertion/@ID` per la loro validità.
- Tempi: UTC, `NotBefore/NotOnOrAfter` con skew limitato e configurabile; `IssueInstant` entro 60 s (regole SPID).
- Redirect: `returnTo` validato con `wp_validate_redirect()`; `RelayState` = token opaco (non l'URL), l'URL sta nello stato server-side.
- Rotte `login` solo GET/POST previsti, rate limit di base (transient per IP) per evitare flooding di AuthnRequest/riempimento transient.
- Admin: `current_user_can('manage_options')`, nonce su ogni azione (rigenera certificato, refresh registry), sanitizzazione input, `esc_*` su ogni output.
- Segreti: chiave privata fuori dalla webroot se possibile, permessi 0600, mai in log/export/backup di opzioni; avviso esplicito su nginx.
- Log: niente attributi personali completi (al massimo CF mascherato); log di errori di validazione con codice, IdP, ID richiesta.
- Provisioning: nessun auto-link per email; username non prevedibile ma deterministico; ruolo di default minimo.
- Disattivazione plugin: nessun comportamento di "tutti autenticati". Gate sempre fail-closed.

---

## 8. Test e validazione

- **Unit test** (PHPUnit senza WP dove possibile; stub minimi di funzioni WP): firma/verifica XML, validator Response (casi §4.3), builder metadata, mappatura errori.
- **Fixture**: `inspirations/wp-auth-gov-proxy/resources/spid-idps.json` (registry); Response SAML di esempio da generare con l'IdP **SPID Demo** (`https://demo.spid.gov.it`) e con il **validator** AgID.
- **Ambienti SPID**: registrare il metadata su `https://demo.spid.gov.it` (test funzionale), poi su `https://validator.spid.gov.it` (suite di test AgID, obbligatoria prima della produzione: Request e Response test; il validator riporta quale regola fallisce — usarlo per sciogliere i dubbi su `Destination`, certificato, ContactPerson). Poi richiesta di adesione AgID (pubblico/privato).
- **CIE**: onboarding su portale CIE (ambiente di **pre-produzione** `preproduzione.idserver.servizicie.interno.gov.it`) con metadata CIE del plugin.
- **Manuale**: login L1/L2/L3, annullamento sull'IdP, errori nr19–nr30, utente nuovo/esistente, logout locale e SLO, replay (rinviare la stessa Response → deve fallire), orologio sfasato, permalink "Semplici", multisite (decidere se supportato), cache plugin attiva.
- Nota ambiente: nella macchina di sviluppo attuale `php` **non è installato** nel PATH (`php: comando non trovato`); installare PHP CLI (con `openssl`, `dom`, `mbstring`) per lint e PHPUnit, oppure usare un container.

---

## 9. Licenza e attribuzioni

`spid-cie-php` è **Apache-2.0**: se si riutilizzano porzioni di codice/template (es. markup dei bottoni, struttura dei ContactPerson, logica di validazione) mantenere header di copyright e un file `NOTICE`. Apache-2.0 è compatibile con GPLv3 ma **non con GPLv2-only**: se si vuole pubblicare su wordpress.org (GPLv2+), dichiarare il plugin `GPLv2 or later` solo se non si incorpora codice Apache-2.0 verbatim, oppure licenziare `GPL-3.0-or-later`. Preferibile **riscrivere** (non copiare) la logica, usando le specifiche AgID come fonte, e citare spid-cie-php come ispirazione. Verificare anche licenze di `spid-sp-access-button` / `cie-graphics` / `spid-graphics` prima di includerli.

---

## 10. Questioni ancora aperte (non bloccanti; scegliere il default indicato se non specificato)

1. **Licenza** del plugin e pubblicazione su wordpress.org (default: `GPL-3.0-or-later`, uso interno, vedi §9).
2. **Multisite**: non supportato nell'MVP (default).
3. **Chiave privata**: path fuori webroot configurabile via costante `WPSPID_PRIVATE_DIR`, fallback in `uploads` protetta (§4.7). Confermare apache/nginx dei siti target.
4. **Dati dell'ente** per i metadata (IPA code o P.IVA, contatti, dati `fpa:` per privati): da inserire dall'admin; servono per registrazione AgID.
5. **Formato di `$_SESSION['govauth_user_data']`** da verificare in `tabs.php` (§5.7).
6. **Migrazione** da `wp-auth-gov-proxy`: nessuna (i cittadini non hanno account WP); basta disattivare il vecchio plugin dopo l'attivazione del nuovo. Nota: l'entityID/metadata già registrati con il vecchio SP vanno **mantenuti uguali** (stesso entityID e stesso certificato, se ancora validi) per non rifare la registrazione AgID → prevedere **import di certificato/chiave esistenti** da admin (oltre alla generazione).

---

## 11. Istruzioni operative per l'AI esecutrice

- Lavora **solo** dentro `wp-content/plugins/wp-spid-cie/` (escluso `inspirations/`, sola lettura). Non modificare il resto di WordPress.
- Non introdurre Composer, `vendor/`, npm obbligatorio a runtime, né download di codice da internet in esecuzione.
- Rispetta le WordPress Coding Standards (sicurezza prima di tutto: `ABSPATH` guard in ogni file, escaping, nonce, capability).
- Procedi per fasi (§6), consegnando test per ogni fase prima di passare alla successiva. La fase 2 (firma/verifica XML) è la più rischiosa: scrivi prima i test negativi.
- Quando le regole SPID non sono chiare dal codice di riferimento, **non indovinare**: implementa il comportamento di spid-php, rendilo configurabile e annota la verifica da fare col validator AgID in un `docs/TODO-validator.md`.
- Documenta in `docs/` (italiano): installazione, configurazione, registrazione metadata presso AgID/CIE, troubleshooting.
- A ogni milestone riepiloga cosa è stato implementato, cosa è testato (e come) e cosa resta da validare in ambiente reale.

---

## 12. Stato dell'implementazione e revisione del codice (2026-11-08)

Una prima implementazione (fasi 1–7 del §6, scheletro) è stata scritta da un'altra AI e poi **rivista e corretta**. Questa sezione descrive lo stato reale: **leggerla prima di continuare**. Ciò che è in questa sezione prevale su eventuali ottimismi del resto del documento.

### 12.1 Come eseguire i test (nessuna dipendenza, nessun Composer)

```bash
# dalla cartella del plugin; richiede solo PHP >= 8.0 con openssl, dom, mbstring
php tests/run.php        # firma XML + validazione Response (31 test, inclusi attacchi)
php tests/run_wp.php     # richiesta, certificati, registry, metadata, replay (24 test, stub WP in memoria)

# senza PHP installato (Docker; la cartella deve stare sotto un path condiviso con Docker):
docker run --rm -v "$PWD":/app -w /app php:8.3-cli sh -c 'php tests/run.php; php tests/run_wp.php'
```
Verificati su PHP 8.0, 8.3 e 8.5. I test sulla firma sono stati controllati con un *mutation test* (verificatore reso inefficace → 6 test d'attacco falliscono): non sono test vuoti. **Ogni modifica a `includes/Xml/` o `includes/Saml/` deve mantenere i test verdi e aggiungerne di nuovi per ogni caso nuovo.**

### 12.2 Difetti trovati nella prima implementazione (ora corretti)

| # | Gravità | Difetto | Correzione |
|---|---|---|---|
| 1 | **Critico** | Il verificatore accettava *qualunque* `ds:Signature` valida nel documento e gli attributi si leggevano con `//saml:Attribute` ovunque → falsificazione dell'identità via signature wrapping. | `SignatureVerifier::verify_element()` prova che **l'elemento specifico** (Assertion) è firmato; ID unico nel documento; una sola `Reference` che punta a quell'ID; transform/algoritmi in allow-list; certificati solo dal registry IdP. Il validatore ammette **una sola Assertion** (figlia diretta della Response) e legge i dati **solo da essa**. |
| 2 | **Critico** | Iniezione XPath: `//*[@ID="` + valore preso dalla `Reference` (controllato dall'attaccante) + `"]`. | Nessuna query XPath con valori esterni: confronto in PHP dell'`URI` con `#` + ID dell'elemento. |
| 3 | **Critico** | `InResponseTo` verificato solo se presente; Issuer/Destination/Recipient/Audience/tempi/livello/attributi obbligatori **non verificati**. | `ResponseValidator` implementa tutto il §4.3 (con ramo CIE separato). Vedi test "Content checks". |
| 4 | **Grave** | `Registry`: i flag `_deleted`/`_disabled` del registry sono stringhe `'Y'`/`'N'`; `! empty('N')` è vero → **tutti gli IdP scartati** (bottone SPID vuoto). | `is_flag_set()` interpreta `Y/N`. Test sul file di snapshot. |
| 5 | **Grave** | Endpoint SSO del registry con chiavi `Binding`/`Location`, il Router cercava `binding`/`location` → login SPID impossibile. | Normalizzazione in `Registry::normalize_endpoints()`. |
| 6 | **Grave** | Valori con `&` passati a `createElementNS(..., $valore)` vengono **troncati**: l'`entityID` di default (`?wpspid=metadata&service=spid`) o un nome ente con `&` rompevano la firma/metadata. | `XmlSecurity::text_element()` (testo escapato); namespace dichiarati con `setAttributeNS`; la firma è calcolata su una copia **ri-parsata** del documento. Test di regressione. |
| 7 | Grave | Richiesta inviata **non firmata** se mancavano chiave/certificato. | `AuthnRequestBuilder`/`Bindings`/`MetadataBuilder` lanciano eccezione senza chiave: mai richieste o metadata non firmati. |
| 8 | Medio | CIE: IdP "mock" senza certificati, `AuthnContextClassRef` `…/cie2.html` inventato. | `CieMetadata` legge endpoint e certificati dal metadata ufficiale (cache 12h); class ref `SpidL{n}` come spid-php; senza certificati il login si **blocca** (fail closed). |
| 9 | Medio | Firma XML incorporata anche nel binding Redirect; livello non limitato (`SpidL99`). | Redirect: solo firma in query; `level` limitato a 1–3. |
| 10 | Medio | Sessione: nessun `session_regenerate_id`, `session_start()` anche per anonimi, nessuna scadenza; logout via GET senza nonce; `returnTo` ignorato. | `Auth/SessionGate` (rigenera ID, flag cookie, scadenza assoluta 2h filtrabile, nessuna sessione per anonimi in lettura); logout con nonce; `returnTo` validato con `wp_validate_redirect`. |
| 11 | Medio | `libxml_disable_entity_loader` (deprecata in 8.0); `.htaccess` sintassi Apache 2.2 (500 su 2.4); chiave scritta con permessi default prima del `chmod`; `import()` non verificava la coppia chiave/certificato. | Corretti (`umask(0077)`, doppia sintassi, `openssl_x509_check_private_key`). |
| 12 | Basso | Fixture del registry letta da `inspirations/`; `uninstall.php` vuoto; `RelayState` usato come ID richiesta. | Snapshot in `resources/spid-idps.json`; uninstall implementato (le chiavi **non** vengono cancellate); correlazione solo via `InResponseTo`. |

### 12.3 Cosa è implementato (e testato) ora

- `Xml/`: caricamento sicuro, firma enveloped, verifica rigorosa. **Testato** (firma/verifica, wrapping, ID duplicati, quote injection, SHA-1, DOCTYPE).
- `Saml/ResponseValidator`: validazione completa SPID + ramo CIE. **Testato** (31 casi).
- `Saml/AuthnRequestBuilder`, `Bindings` (Redirect firmato in query, POST con XMLDSig), `MetadataBuilder` (firmato, base: manca ContactPerson/estensioni). **Testato**.
- `Idp/Registry` (SPID, con snapshot di fallback), `Idp/CieMetadata`, `Cert/CertificateManager`, `State/RequestStore` (consumo singolo), `State/ReplayCache`, `Auth/SessionGate`, `Http/Router`, `Api.php`.

- **Archiviazione dati e requisiti** (vedi `docs/STORAGE.md`): chiavi, certificati e metadata registrato in `data/` dentro il plugin (override: `WPSPID_PRIVATE_DIR`); chiave in `*.key.php` con guard `<?php exit; ?>` (verificato su nginx: 200, 0 byte); `Support/DataPreserver` mette `data/` al riparo da aggiornamento e reinstallazione (**provato con un vero `wp plugin install --force`**, che prima del fix cancellava i dati: `hook_extra` non ha la chiave `plugin` nelle reinstallazioni, serve `upgrader_source_selection`); `Support/Requirements` (probe pratico di OpenSSL all'attivazione e nell'admin, blocca generazione/login se fallisce); `Saml/MetadataSnapshot` (metadata registrato + avviso se cambia, confronto normalizzato). Migrazione automatica dalla vecchia cartella in `uploads/`. **Testato**: 102 test (`run_wp.php`) su PHP 8.0/8.2/8.3/8.5. **Non testato**: un vero hosting condiviso con `disable_functions` o OpenSSL limitato (simulato con override nei test); aggiornamento da zip con deploy `rsync --delete` e eliminazione del plugin (dati persi per scelta, documentato); pulsanti admin di download/salvataggio snapshot solo come render, non cliccati in un browser.

### 12.4 Cosa NON è ancora fatto (prossimi passi, in ordine)

1. **Pagina impostazioni** (§5.6): oggi `wpspid_options` non è scrivibile da admin → entityID, tipo ente, dati organizzazione, attributi, livello CIE, `destination_mode`, import/generazione certificato **non configurabili**.
2. **Metadata completo**: `ContactPerson` con estensioni `spid:`/`fpa:`/`cie:` (§4.5), `Organization` con dati reali, subject del certificato conforme all'Avviso n.29 (§4.7). **Senza questo il metadata non passa il validator.**
3. **UI**: bottoni SPID/CIE con lo stile del tema ASL (§5.7), pagina di scelta IdP, shortcode, aggancio al filtro `dci_area_personale`. Verificare il formato di `$_SESSION['govauth_user_data']` letto da `wp-pa-theme/template-parts/prenotazione/tabs.php` (il plugin ora salva l'array degli attributi `fiscalNumber`, `name`, … con `fiscalNumber` già senza `TINIT-`).
4. **SLO completo**: oggi il logout è **solo locale**. Mancano `LogoutRequest` firmata verso l'IdP (con `NameID` = entityID IdP e `SessionIndex`, già salvati nella sessione, §4.4) e la gestione di `LogoutResponse`/richieste dall'IdP con verifica di firma.
5. **Refresh schedulato** di registry e metadata CIE (WP-Cron) e pulsante di refresh in admin; fix dell'URL di pre-produzione CIE (§ `docs/TODO-validator.md`, punto 6).
6. **Login CSRF** (rischio noto, non mitigato): un attaccante può far postare alla vittima una propria Response valida (legata a una *sua* richiesta) e collegarla alla sessione della vittima. Mitigazione consigliata: cookie di binding `SameSite=None; Secure` impostato al login e verificato all'ACS (solo HTTPS), oppure `RelayState` opaco legato al browser.
7. **Rate limiting** della rotta `login` (flooding di transient) e `Cache-Control` verificato con plugin di cache reali.
8. **Validazione contro ambienti reali**: SPID Demo → Validator AgID → CIE pre-produzione. Elenco dei punti incerti in `docs/TODO-validator.md`. **Nessun test è stato ancora eseguito contro un IdP reale.**
9. Traduzioni (`languages/`), `readme.txt`, documentazione in `docs/`, pacchettizzazione senza `inspirations/`, `tests/`.

### 12.5 Regole per chi continua

- **Non reintrodurre** letture di dati da nodi non coperti dalla firma verificata, né XPath con valori provenienti da input.
- Ogni stringa dinamica in XML passa da `XmlSecurity::text_element()` o `setAttribute` (mai come terzo parametro di `createElementNS`).
- Nuovi controlli sulla Response → prima un test negativo in `tests/run.php`, poi il codice.
- Le questioni di conformità SPID non risolvibili offline vanno annotate in `docs/TODO-validator.md`, non "indovinate".

