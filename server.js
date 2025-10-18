// server.js
// Minimalni Express + Kerberos (SPNEGO) primer sa .env konfiguracijom

import express from "express";
import path from "path";
import dotenv from "dotenv";
import { fileURLToPath } from "url";
import kerberos from "kerberos";
const { initializeServer } = kerberos;

// Load .env konfiguraciju
dotenv.config();

// Resolve __dirname (jer koristimo ES modules)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Konfiguracija iz .env fajla
const HOST = process.env.HOST || "0.0.0.0";
const PORT = process.env.PORT || 3000;
const REALM = process.env.REALM || "CONTABOSERVER.NET";
const FQDN = process.env.FQDN || "localhost";
const SERVICE = `HTTP@${FQDN}`;

// Express aplikacija
const app = express();
app.use(express.static(__dirname));

// ➕ Ruta za osnovnu stranu — ispisuje info o serveru
app.get("/", (req, res) => {
    const info = `
────────────────────────────────────────────
🚀 Kerberos SPNEGO demo server pokrenut
🌐 Adresa:   http://${FQDN}:${PORT}
📡 Service:  ${SERVICE}
🏠 Realm:    ${REALM}
────────────────────────────────────────────
`;
    res.type("text/plain").send(info);
});

// Kerberos SPNEGO endpoint
app.get("/api/auth", async (req, res) => {
    try {
        const authz = req.headers["authorization"] || "";

        if (!authz.startsWith("Negotiate ")) {
            res.set("WWW-Authenticate", "Negotiate");
            return res.status(401).send("Negotiate");
        }

        const negotiateToken = authz.slice("Negotiate ".length);
        const server = await initializeServer(SERVICE);
        const outToken = await server.step(negotiateToken);

        if (!server.contextComplete) {
            if (outToken) res.set("WWW-Authenticate", `Negotiate ${outToken}`);
            return res.status(401).send("Continue SPNEGO");
        }

        const clientUser = server.username; // npr. vanja@CONTABOSERVER.NET
        return res.json({
            ok: true,
            user: clientUser,
            service: SERVICE,
            realm: REALM,
            message: "Kerberos SPNEGO authentication succeeded",
        });
    } catch (err) {
        console.error("[KERBEROS ERROR]", err);
        if (err.outputToken) {
            res.set("WWW-Authenticate", `Negotiate ${err.outputToken}`);
            return res.status(401).send("Continue SPNEGO (error path)");
        }
        return res.status(401).send("Unauthorized");
    }
});

// Health check endpoint
app.get("/healthz", (req, res) => res.json({ ok: true }));

// Pokretanje servera
app.listen(PORT, HOST, () => {
    console.log("────────────────────────────────────────────");
    console.log("🚀 Kerberos SPNEGO demo server pokrenut");
    console.log(`🌐 Adresa:   http://${FQDN}:${PORT}`);
    console.log(`📡 Service:  ${SERVICE}`);
    console.log(`🏠 Realm:    ${REALM}`);
    console.log("────────────────────────────────────────────");
});