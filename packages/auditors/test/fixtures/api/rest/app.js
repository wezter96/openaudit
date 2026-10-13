const express = require("express");
const app = express();
app.post("/api/login", (req, res) => res.json({ ok: true }));
app.listen(3000);
