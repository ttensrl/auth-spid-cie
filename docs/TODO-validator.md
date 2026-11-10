# Punti da verificare con il validator AgID / ambienti reali

Il codice replica il comportamento di `spid-cie-php`. Questi punti **non sono verificabili offline** e vanno confermati con
`https://validator.spid.gov.it`, SPID Demo e l'ambiente CIE di pre-produzione.

1. **`Destination` dell'AuthnRequest**: default `entity_id` (come spid-php). Opzione `destination_mode = sso_url` per usare l'URL SSO. Verificare quale è accettato.
2. **Firma nel binding Redirect**: la richiesta Redirect NON contiene XMLDSig, solo la firma nella query (`SigAlg`+`Signature`). Verificare con il validator.
3. **Certificato SP**: i campi del subject (Avviso SPID n.29 v.3: `organizationIdentifier`, `serialNumber`, `uri`, …) non sono ancora generati. Oggi: solo commonName/organizationName/countryName.
4. **ContactPerson con estensioni** `spid:`/`fpa:`/`cie:` nel metadata: non ancora implementato (serve la pagina impostazioni con i dati dell'ente).
5. **CIE**: ramo di validazione "permissivo" come spid-php (Issuer Format, NameID Format/NameQualifier, presenza `NotBefore/NotOnOrAfter`, valore di `AuthnContextClassRef` non SPID). Restano obbligatori firma, Issuer, Destination, InResponseTo, Recipient, Audience, tempi. Restringere dopo test reali.
6. **Metadata IdP CIE di pre-produzione**: l'URL `https://preproduzione.idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata` risponde **404** (verificato 2026-11-08); quello di produzione funziona. Finché non si trova l'URL corretto, il login CIE di test si blocca volutamente (nessun certificato → fail closed).
7. **Livello CIE**: default 2 (opzione `cie_level`). La CIE riceve `AuthnContextClassRef` `https://www.spid.gov.it/SpidL{n}` come in spid-php.
8. **Tolleranze temporali**: `IssueInstant` max 60 s di età (regola SPID), `NotBefore/NotOnOrAfter` skew 180 s. Possono richiedere taratura con IdP reali.
9. **Mapping errori nr19–nr30**: implementati solo nr19–nr23 e nr25; gli altri mostrano un messaggio generico.
