# Dati del plugin: dove stanno, come sono protetti, cosa si perde

## Dove

Tutto nel **database di WordPress**, non in file. Il plugin non scrive nulla nella propria cartella né in `uploads/`.

| Opzione | Contenuto |
|---|---|
| `authspidcie_cert_spid`, `authspidcie_cert_cie` | chiave privata dell'SP (cifrata o no, vedi sotto) e certificato |
| `authspidcie_registered_spid`, `authspidcie_registered_cie` | metadata registrato presso AgID/CIE + hash, data, nota |
| `authspidcie_options` | impostazioni dell'ente (ragione sociale, contatti, livelli, ...), per sito |

Sono opzioni **di rete** (`get_site_option`/`update_site_option`): in un multisite stanno in `sitemeta` e c'è **un solo certificato per tutta la rete**, come prima; in un sito singolo WordPress le scrive in `options` con `autoload = 'no'`, quindi la chiave non viene caricata a ogni richiesta. Le pagine pubbliche non la leggono mai: serve solo per firmare AuthnRequest e metadata.

Conseguenza: **aggiornare, reinstallare, copiare la cartella del plugin o fare un deploy con `rsync --delete` non fa perdere niente.** Un filesystem in sola lettura non è un problema.

## Chiave privata: in chiaro o cifrata

Per default la chiave è salvata **in chiaro** nel database: chi ha un dump o un backup del database ha la chiave. Se questo non va bene, **cifrala** definendo in `wp-config.php` un segreto lungo e casuale:

```php
define( 'AUTHSPIDCIE_SECRET', 'incolla-qui-il-valore-generato' );
```

Generarlo: `php -r "echo bin2hex(random_bytes(32));"`. Conservalo con le altre credenziali (gestore di password, backup separato dal database).

- Cifratura: **libsodium** (`sodium_crypto_secretbox`, XSalsa20-Poly1305), nonce casuale a ogni salvataggio; la chiave di cifratura si deriva dal segreto con `sodium_crypto_generichash` e un contesto fisso del plugin. Serve l'estensione PHP `sodium` (inclusa in PHP dalla 7.2).
- Il valore salvato porta un marcatore di versione e di "cifrato sì/no" e l'impronta breve della chiave derivata. Così il plugin sa distinguere i casi qui sotto e **non restituisce mai una chiave sbagliata**.
- **Non si cifra con i salt di WordPress**: ruotarli (si fa dopo un'intrusione) renderebbe la chiave illeggibile.

| Situazione | Cosa succede |
|---|---|
| Chiave cifrata e `AUTHSPIDCIE_SECRET` corretta | tutto funziona; il pannello dice "cifrata" |
| Chiave in chiaro e costante **non** definita | funziona; il pannello avvisa che i backup contengono la chiave |
| Chiave in chiaro e costante definita **dopo** | funziona; il pannello avvisa e offre **Cifra ora** (si cifra anche al prossimo salvataggio) |
| Chiave cifrata e costante **assente** | chiave illeggibile: login e metadata di quel servizio disattivati, avviso in admin |
| Chiave cifrata e costante **diversa** | idem (l'impronta non corrisponde) |
| Dato alterato o formato sconosciuto | idem, "dato danneggiato" |
| Costante definita ma manca l'estensione `sodium` | bloccato, con il messaggio dedicato: abilita l'estensione o togli la costante |

### Se perdi o cambi `AUTHSPIDCIE_SECRET`

La chiave cifrata **non si può recuperare**. L'avviso in admin lo dice chiaramente: *ripristina la costante `AUTHSPIDCIE_SECRET` originale oppure rigenera il certificato*. Rigenerare significa che **il metadata cambia e va ri-registrato presso AgID/CIE**. Il plugin non prova mai a indovinare il segreto.

### Backup del database

Includono certificato e chiave. Con `AUTHSPIDCIE_SECRET` e il segreto fuori dal dump, il backup da solo non basta a usare la chiave. Senza, **trattali come segreti**.

## Migrazione dalle versioni precedenti (file)

Le prime versioni tenevano i dati in `wp-content/plugins/auth-spid-cie/data/` (chiave `*.key.php`, certificato, metadata registrato) e, ancora prima, in `uploads/wp-spid-cie-private/`. Al primo caricamento il plugin li sposta nel database, in questo ordine:

1. copia nel database;
2. **rilegge** e verifica che chiave e certificato corrispondano (`openssl_x509_check_private_key`) e che il metadata registrato sia identico;
3. **solo dopo** cancella i vecchi file e la cartella vuota (anche `.htaccess`, `index.php`, `.gitignore` di protezione).

Se un passo fallisce (coppia non valida, un certificato diverso già nel database, salvataggio non riuscito) **non cancella niente**: i file restano dove sono e il pannello mostra un avviso con il motivo. Si può rilanciare: è idempotente. Se `AUTHSPIDCIE_SECRET` è definita al momento della migrazione, la chiave entra nel database già cifrata.

Chi aggiorna da una versione che usava `data/`: l'aggiornamento di WordPress rimette `data/` al suo posto (lo faceva la vecchia versione) e la nuova la migra.

## Eliminazione del plugin

`uninstall.php` cancella **sempre** i dati temporanei: sessioni dei cittadini, richieste in corso, anti-replay, elenco IdP in cache, esito della verifica OpenSSL.

Per default **non** cancella certificato, chiave, metadata registrato e impostazioni dell'ente: rifare la registrazione presso AgID/CIE costa giorni, e un'eliminazione per errore o una reinstallazione non deve farla perdere. Per cancellare tutto:

```php
define( 'AUTHSPIDCIE_REMOVE_DATA_ON_UNINSTALL', true );
```

(in `wp-config.php`, prima di eliminare il plugin). In multisite vale per tutta la rete.

## Requisiti del server (OpenSSL)

Il plugin usa l'estensione PHP `openssl`, non il comando `openssl`. `Support/Requirements`:

- all'**attivazione**: controlla estensioni e funzioni (anche quelle in `disable_functions`) e prova **davvero** a generare chiave, CSR e certificato SPID e CIE; se fallisce l'attivazione viene rifiutata con la causa;
- a **ogni caricamento**: se l'ultima verifica (cache 12 ore) è fallita il login, l'ACS e i metadata restano spenti e compare un avviso con le cause;
- nell'admin: riga "Server" con il risultato e il pulsante *Ricontrolla*; generazione e import dei certificati sono bloccati se il server non è idoneo.

Cause tipiche su hosting condiviso: estensione assente, funzioni OpenSSL disattivate, cartella temporanea di PHP non scrivibile, build di OpenSSL che rifiuta gli OID dell'Avviso SPID.

## Metadata registrato

Il metadata si genera al volo (`?authspidcie=metadata&service=spid|cie`). Dopo la registrazione presso AgID/CIE si salva da *Impostazioni → SPID/CIE → Stato* ("Salva come registrato"). Da quel momento il plugin segnala se il metadata attuale differisce da quello registrato (confronto sul metadata normalizzato: ID casuale, `validUntil` e firma non contano). Se cambia, la registrazione va ripetuta.
