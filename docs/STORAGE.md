# Dati del plugin: dove stanno, come sono protetti, cosa si perde

## Dove

Tutto in **`wp-content/plugins/auth-spid-cie/data/`** (percorso alternativo: costante `WPSPID_PRIVATE_DIR` in `wp-config.php`, per chi può usare una cartella privata).

| File | Contenuto | Pubblico? |
|---|---|---|
| `spid-sp.key.php`, `cie-sp.key.php` | chiave privata dell'SP (permessi 0600) | **No**, vedi protezione |
| `spid-sp.crt`, `cie-sp.crt` | certificato | sì (è pubblico per natura) |
| `registered-spid.xml/.json`, `registered-cie.*` | metadata registrato presso AgID/CIE + hash, data, nota | sì (è pubblico per natura) |
| `.htaccess`, `index.php`, `.gitignore` | protezione e esclusione da git | – |

## Come è protetta la chiave

1. Il file è un `.php` che inizia con `<?php exit; ?>`: se un web server lo esegue (e per un `.php` lo fa) non stampa nulla. **Verificato su nginx**: `GET .../data/spid-sp.key.php` → HTTP 200, 0 byte.
2. `.htaccess` (Apache 2.4 e 2.2) nega l'accesso alla cartella; nginx lo ignora ma blocca comunque `/.ht*` nella configurazione standard.
3. `index.php` evita l'elenco della cartella; permessi 0600 sui file della chiave.
4. `data/.gitignore` esclude tutto tranne i tre file di protezione.
5. Non si cifra con i salt di WordPress: ruotarli (si fa dopo un'intrusione) renderebbe la chiave illeggibile e farebbe perdere la registrazione.

Limite: la protezione 1 vale se il server esegue PHP in quella cartella. Non esporre mai `data/` con regole che servono i `.php` come testo.

## Aggiornamento del plugin: i dati sopravvivono

WordPress aggiorna un plugin **cancellando la cartella precedente**. `Support/DataPreserver` copia `data/` in `wp-content/upgrade/wpspid-preserve-…` prima, la rimette dopo e verifica che i file siano identici (hash e permessi).

- Copre: aggiornamenti, **upload con "sostituisci quello attuale"**, `wp plugin install --force`.
- Se la copia di sicurezza non riesce, l'operazione viene **annullata**.
- Se il ripristino non riesce, la copia resta sul disco e compare un avviso con il percorso.
- Testato: unit test e una vera reinstallazione con `wp plugin install --force` su WordPress 7.1 / PHP 8.2 (dati identici).

## Cosa si perde

- **Eliminare il plugin** dalla schermata Plugin: la cartella viene cancellata con tutto. Il certificato registrato con AgID/CIE va rifatto. L'admin lo ricorda nella riga "Dati". Prima: scaricare certificato e metadata registrato.
- **Deploy con `rsync --delete`** o reupload via FTP della cartella del plugin: aggiungere `--exclude data/` oppure usare `WPSPID_PRIVATE_DIR`.
- Aggiornamento interrotto a metà (server che va giù): la copia in `wp-content/upgrade/` può essere recuperata a mano.
- I backup di sito (Duplicator e simili) includono la cartella e quindi la chiave: trattarli come segreti.

## Requisiti del server (OpenSSL)

Il plugin usa l'estensione PHP `openssl`, non il comando `openssl`. `Support/Requirements`:

- all'**attivazione**: controlla estensioni e funzioni (anche quelle in `disable_functions`) e prova **davvero** a generare chiave, CSR e certificato SPID e CIE; se fallisce l'attivazione viene rifiutata con la causa;
- a **ogni caricamento**: se l'ultima verifica (cache 12 ore) è fallita il login, l'ACS e i metadata restano spenti e compare un avviso con le cause;
- nell'admin: riga "Server" con il risultato e il pulsante *Ricontrolla*; generazione e import dei certificati sono bloccati se il server non è idoneo.

Cause tipiche su hosting condiviso: estensione assente, funzioni OpenSSL disattivate, cartella temporanea di PHP non scrivibile, build di OpenSSL che rifiuta gli OID dell'Avviso SPID.

## Metadata registrato

Il metadata si genera al volo (`?wpspid=metadata&service=spid|cie`). Dopo la registrazione presso AgID/CIE si salva da *Impostazioni → SPID/CIE → Stato* ("Salva come registrato"). Da quel momento il plugin segnala se il metadata attuale differisce da quello registrato (confronto sul metadata normalizzato: ID casuale, `validUntil` e firma non contano). Se cambia, la registrazione va ripetuta.
