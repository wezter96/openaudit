// Safe patterns that code.security must not flag.
import { execFile } from "node:child_process";

declare const db: { query: (q: string, params: unknown[]) => Promise<unknown> };
declare const sql: (s: TemplateStringsArray, ...v: unknown[]) => unknown;

export const getUser = (id: string) =>
	db.query("SELECT * FROM users WHERE id = $1", [id]);

export const tagged = (id: string) => sql`SELECT * FROM users WHERE id = ${id}`;

export const list = (dir: string) => execFile("ls", ["-la", dir]);

type Element = { textContent: string; innerHTML: string };

export const show = (el: Element, text: string) => {
	el.textContent = text;
	el.innerHTML = "";
};

export const shuffle = <T>(items: T[]) =>
	items.sort(() => Math.random() - 0.5);

// eval(userInput) in a comment is fine
export const ns = "http://www.w3.org/2000/svg";
