import { readFileSync } from "node:fs";
import express from "express";

const config = readFileSync("config.json", "utf8");
const app = express();

app.get("/report", (_req, res) => {
	const template = readFileSync("report.html", "utf8");
	res.send(template.replace("{{config}}", config));
});
