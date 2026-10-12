import type { Playbook } from "../playbook";
import { compose, REPORTING } from "./shared";

export const injection: Playbook = {
	id: "agent.injection",
	title: "Injection & data-flow review",
	summary:
		"Traces untrusted input from sources to dangerous sinks (SQL/NoSQL, shell, outbound HTTP, HTML, filesystem, templates, deserializers) and reports only reachable, unsanitised paths.",
	categories: ["security"],
	targets: ["codebase"],
	needs: ["code"],
	checklist: [
		"Listed untrusted sources: request params/query/body/headers/cookies, uploaded files, webhook payloads, message-queue payloads, third-party API responses, database fields written by users",
		"Searched for SQL sinks built with string concatenation/interpolation or raw-query escape hatches",
		"Searched for NoSQL sinks accepting operator objects ($where, $ne, $regex) from user input",
		"Searched for OS command execution (exec/spawn with shell, system, popen, backticks) with user-controlled arguments",
		"Searched for server-side requests to user-controlled URLs (SSRF), including redirects and URL parsers",
		"Searched for XSS sinks: dangerouslySetInnerHTML, v-html, innerHTML, document.write, unescaped template output, markdown/HTML rendering without sanitisation",
		"Searched for filesystem access with user-controlled paths (traversal, zip-slip, arbitrary write)",
		"Searched for server-side template injection (templates compiled from user input)",
		"Searched for unsafe deserialization (pickle, yaml.load, Java/PHP/.NET deserializers, node-serialize) and prototype pollution",
		"Searched for code evaluation (eval, new Function, vm, dynamic import/require) and header/log injection (CRLF)",
		"For each candidate, confirmed reachability from a source and the absence of effective validation, parameterisation or encoding",
	],
	instructions: compose(
		`# Injection & data-flow review

## Scope

Application code (server, workers, CLIs, server-rendered and client-side UI) where untrusted data can reach an interpreter or a dangerous API. Deterministic pattern scanners have likely flagged obvious sinks already; your job is the judgment they cannot make: **is this sink actually reachable with attacker-controlled data, and is that data neutralised on the way?**

## Method

1. **Map sources.** Find where untrusted data enters: HTTP handlers (params, query, body, headers, cookies, files), GraphQL args, RPC inputs, webhooks, queue/stream consumers, CLI args in services, data read back from the database that users originally wrote (stored injection), and responses from third-party APIs.
2. **Map sinks.** Grep for dangerous APIs in the stack you find. Examples (not exhaustive):
   - SQL: string-built queries, \`$queryRawUnsafe\`, \`sequelize.query\` with interpolation, \`knex.raw\`, \`sql.raw\`, \`db.execute(f"...")\`, \`cursor.execute("..." % x)\`, \`.whereRaw\`, \`ORDER BY\` / column names from input.
   - NoSQL: Mongo queries built from \`req.body\` objects (operator injection), \`$where\`, \`mapReduce\`, Elasticsearch script queries.
   - Command: \`child_process.exec\`, \`spawn(..., { shell: true })\`, \`execSync\`, \`os.system\`, \`subprocess(..., shell=True)\`, \`Runtime.exec\`, backticks, \`system()\`; also argument injection (\`git\`, \`ffmpeg\`, \`curl\` options starting with \`-\`).
   - SSRF: \`fetch\`/\`axios\`/\`got\`/\`requests\`/\`http.Get\` with a user-influenced URL or host; image/PDF/HTML renderers, webhook testers, URL previews, import-from-URL features.
   - XSS: \`dangerouslySetInnerHTML\`, \`v-html\`, \`{@html}\`, \`innerHTML\`, \`outerHTML\`, \`insertAdjacentHTML\`, \`document.write\`, jQuery \`.html()\`, \`|safe\` / \`mark_safe\` / \`raw\` / \`<%-\` / \`{{{ }}}\`, \`href\`/\`src\` built from input (\`javascript:\` URLs), markdown rendering with HTML enabled.
   - Path traversal: \`fs.readFile\`/\`sendFile\`/\`open()\`/\`File\` with joined user paths, archive extraction without entry-path checks (zip-slip), uploads stored under user-controlled names.
   - Template injection: \`render_template_string\`, \`Template(user_input)\`, \`ejs.render(userTemplate)\`, Handlebars/Nunjucks/Jinja/Twig compiling user-supplied templates.
   - Deserialization: \`pickle.loads\`, \`yaml.load\` without SafeLoader, \`ObjectInputStream\`, \`unserialize\`, \`BinaryFormatter\`, \`node-serialize\`; prototype pollution via deep-merge of request bodies.
   - Code eval: \`eval\`, \`new Function\`, \`vm.runIn*\`, \`setTimeout(string)\`, dynamic \`require\`/\`import\` of user paths.
   - Header/log injection: user data in response headers or redirects (\`Location\`) without CRLF filtering; open redirects.
3. **Connect them.** For each sink, trace backwards to a source (or forwards from sources to sinks). Follow helper functions, wrappers and ORM layers across files. Write down the path: \`handler → service.fn → repo.fn → sink\`.
4. **Check neutralisation.** Is there parameterisation (bound parameters, ORM query builders), allow-list validation (enum, regex anchored on both ends, numeric parse), schema validation (zod/joi/pydantic) that actually constrains the dangerous characters, context-correct output encoding (framework auto-escaping), path canonicalisation + prefix check, URL allow-listing with DNS-rebinding/redirect handling, or a sanitiser (DOMPurify, bleach) applied **after** the last transformation? Note validation that is bypassable (deny-lists, client-side only, checked before decoding).
5. **Assess impact.** Who can reach the source (anonymous, any user, admin only)? What does the sink give an attacker (data read, RCE, internal network access, account takeover via XSS)?

## Severity rubric

- **critical** — unauthenticated RCE, SQL injection or SSRF to cloud metadata/internal admin services; arbitrary file write.
- **high** — authenticated RCE/SQLi/SSRF, stored XSS in a page other users view, arbitrary file read, unsafe deserialization of request data.
- **medium** — reflected XSS, SSRF limited to external hosts or blind, path traversal limited to non-sensitive dirs, NoSQL operator injection with limited impact, open redirect usable for phishing/OAuth token theft.
- **low** — injection reachable only by highly privileged users in a way that does not cross a trust boundary, or requiring unlikely preconditions.
- **info** — risky patterns that are currently safe but fragile (e.g. raw query helper only called with constants).

## What NOT to report

- Sinks whose inputs are constants, configuration or values from trusted operators only.
- Queries using bound parameters or ORM builders correctly, framework-escaped template output, sanitised HTML.
- \`dangerouslySetInnerHTML\` on content produced at build time from repository files (e.g. MDX, i18n strings) unless users can edit that content.
- "Missing input validation" without a concrete sink and impact.
- Test code, fixtures and scripts that are never deployed.`,
		REPORTING,
	),
};
