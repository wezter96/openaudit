// Intentionally vulnerable fixture for code.security tests.
const { exec } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");
const cors = require("cors");
const express = require("express");

const app = express();
app.use(cors({ origin: "*", credentials: true }));

app.get("/calc", (req, res) => {
	res.send(String(eval(req.query.expr)));
});

app.get("/ping", (req, res) => {
	exec(`ping -c 1 ${req.query.host}`, (_err, out) => res.send(out));
});

app.get("/user", async (req, res) => {
	const rows = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);
	res.json(rows);
});

app.get("/go", (req, res) => {
	res.redirect(req.query.next);
});

app.get("/file", (req, res) => {
	const p = path.join(__dirname, "uploads", req.params.name);
	res.send(fs.readFileSync(p));
});

function hashPassword(password) {
	return crypto.createHash("md5").update(password).digest("hex");
}

function checksum(buf) {
	return crypto.createHash("sha1").update(buf).digest("hex");
}

const resetToken = Math.random().toString(36).slice(2);

const agent = new https.Agent({ rejectUnauthorized: false });

function render(el, html) {
	el.innerHTML = html;
}

const API = "http://api.payments-provider.com/v1/charge";
const LOCAL = "http://localhost:3000/api";

module.exports = { hashPassword, checksum, resetToken, agent, render, API, LOCAL };
