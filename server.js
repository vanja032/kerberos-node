// server.js
// Minimalni Express server sa Kerberos (SPNEGO) autentifikacijom
// Servisni principal: HTTP/<fqdn>@REALM u /etc/krb5.keytab

const express = require('express');
const path = require('path');
const { initializeServer } = require('kerberos');

// >>>> PODESI OVO NA SVOJ FQDN I REALM <<<<
const FQDN = 'vmi2382338.contaboserver.net';
const SERVICE = `HTTP@${FQDN}`; // oblik koji Kerberos modul očekuje (HTTP@host)

const app = express();
const PORT = process.env.PORT || 3000;

// Statika (index.html u istom folderu)
app.use(express.static(__dirname));

// SPNEGO endpoint: pregovara Kerberos sa klijentom
app.get('/api/auth', async (req, res) => {
    try {
        const authz = req.headers['authorization'] || '';

        // 1) Ako nema 'Authorization: Negotiate ...', tražimo ga (401 + WWW-Authenticate)
        if (!authz.startsWith('Negotiate ')) {
            res.set('WWW-Authenticate', 'Negotiate');
            return res.status(401).send('Negotiate');
        }

        const negotiateToken = authz.slice('Negotiate '.length);

        // 2) Inicijalizuj Kerberos server context kao "acceptor"
        const server = await initializeServer(SERVICE);

        // 3) Predaj klijentski SPNEGO token
        const outToken = await server.step(negotiateToken);

        // Ako je potreban još jedan krug (retko u praksi, ali standard to dozvoljava)
        if (!server.contextComplete) {
            if (outToken) res.set('WWW-Authenticate', `Negotiate ${outToken}`);
            return res.status(401).send('Continue SPNEGO');
        }

        // 4) Autentifikacija uspešna — dobijamo identitet korisnika
        const clientUser = server.username; // npr. 'vanja@CONTABOSERVER.NET'

        return res.json({
            ok: true,
            user: clientUser,
            service: SERVICE,
            message: 'Kerberos SPNEGO authentication succeeded'
        });

    } catch (err) {
        console.error('[KERBEROS ERROR]', err);
        // Ako imamo izlazni token, pošalji ga nazad u WWW-Authenticate za još jedan krug
        if (err.outputToken) {
            res.set('WWW-Authenticate', `Negotiate ${err.outputToken}`);
            return res.status(401).send('Continue SPNEGO (error path)');
        }
        return res.status(401).send('Unauthorized');
    }
});

// Health-check (bez auth)
app.get('/healthz', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
    console.log(`Kerberos demo server listening on http://${FQDN}:${PORT}`);
    console.log(`Test SPNEGO endpoint: http://${FQDN}:${PORT}/api/auth`);
});