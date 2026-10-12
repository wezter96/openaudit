import type { Playbook } from "../playbook";
import { compose, REPORTING, RESPONSIBLE_USE } from "./shared";

export const privacy: Playbook = {
	id: "agent.privacy",
	title: "Privacy & data-protection review",
	summary:
		"Builds a personal-data inventory and traces its flows — storage, logging, third parties, consent, retention and deletion — against GDPR/CCPA expectations.",
	categories: ["privacy", "compliance"],
	targets: ["codebase", "url"],
	needs: ["code", "network"],
	checklist: [
		"Built an inventory of personal data collected (fields, forms, tables, events) and its sensitivity (special categories, children, financial, precise location, government ids)",
		"Traced where personal data is stored, replicated and backed up",
		"Checked logs, error trackers, analytics events and URLs for personal data",
		"Listed third parties receiving personal data (analytics, ads, CRM, email, support, AI/LLM APIs, CDNs) and what is sent",
		"Checked consent: trackers and non-essential cookies loaded before consent, consent choices honoured, Global Privacy Control / Do Not Track handling where claimed",
		"Checked retention and deletion: account deletion removes or anonymises data across tables, files, third parties and backups policy",
		"Checked data-subject rights support: access/export, rectification, deletion, objection/opt-out of sale/sharing",
		"Checked privacy notice / cookie policy presence and consistency with observed behaviour (for URL targets)",
		"Checked transport and at-rest protection for sensitive fields (encryption, hashing, masking in UI and exports)",
		"Checked data minimisation: collected fields that are never used, over-broad scopes and permissions",
	],
	instructions: compose(
		`# Privacy & data-protection review

## Scope

- **Codebase targets:** data models, forms and validators, API handlers, analytics/tracking code, logging, third-party SDK integrations, background jobs, account deletion/export code, cookie/consent code.
- **URL targets:** what a visitor's browser actually does: cookies set, third-party requests made before and after consent, privacy notice and cookie banner content, forms and the data they collect. Use passive observation only (load pages, read HTML/headers/cookies). Do not submit forms with personal data.

This is an engineering review against common GDPR/UK GDPR/CCPA/CPRA expectations, not legal advice. Phrase findings as risks and concrete engineering gaps.

## Method

1. **Inventory personal data.** From schemas/models/migrations, forms, API payload types and analytics event definitions, list personal data fields: identifiers (name, email, phone, address, IP, device ids, cookie ids), account data, content users create, payment data, location, health/biometric/other special categories, children's data. Note where each is stored.
2. **Trace flows.** For the important fields, follow them from collection to storage, to internal consumers (search indexes, caches, data warehouse, logs), and to external recipients. Grep for analytics/ads/CRM/email/support/error-tracking/LLM SDKs (Segment, GA/gtag, Meta Pixel, Mixpanel, Amplitude, PostHog, Hotjar, FullStory, Intercom, HubSpot, Sentry, Datadog, OpenAI/Anthropic clients) and inspect what properties are sent (\`identify\`, \`track\`, \`setUser\`, prompt contents).
3. **Logging & telemetry.** Look for personal data in log statements, request logs (bodies, query strings), error tracker context (\`setUser\` with email, breadcrumbs with form values), session replay without input masking, and personal data placed in URLs (ends up in logs, referrers and analytics).
4. **Consent.** Check whether non-essential cookies/trackers load before consent (scripts in the document head, SDK init at app start), whether the consent state gates SDK initialisation, whether rejecting is as easy as accepting, and whether choices persist. For URL targets, observe the initial page load: cookies set and third-party requests fired with no interaction.
5. **Retention & deletion.** Find account-deletion and data-retention code. Check that deletion covers all tables holding the user's data (including soft-deleted rows, uploads/object storage, search indexes, caches) and third parties (email/CRM/analytics deletion APIs), and that retention limits exist for logs, events and inactive accounts.
6. **Data-subject rights.** Look for export/download-my-data, profile editing, deletion, marketing opt-out and "do not sell or share" mechanisms; note what is missing for the product's apparent audience.
7. **Protection.** Sensitive fields encrypted or hashed where appropriate (government ids, tokens), masked in admin UIs, exports and support tools; access to personal data restricted to the right roles; personal data not exposed in public APIs, client bundles or SEO-indexed pages.
8. **Minimisation.** Fields collected but never used, OAuth scopes or mobile permissions broader than needed, full birthdates where an age check suffices, precise location where coarse would do.
9. **Notice consistency (URL targets).** Is there a privacy notice and cookie policy linked from every page? Do the third parties you observe appear in it?

## Severity rubric

- **critical** — special-category, children's or financial data exposed publicly or to unauthorised parties; personal data of many users leaked via a public endpoint.
- **high** — personal data sent to third parties without a consent mechanism where one is required, passwords/tokens/full card data in logs, deletion that leaves the bulk of a user's data behind, session replay recording sensitive inputs.
- **medium** — personal data in logs/URLs/error trackers, trackers loading before consent, no retention for event/log data, missing export or deletion paths, privacy notice missing recipients you observed.
- **low** — minimisation issues, missing masking in internal tools, minor notice inconsistencies.
- **info** — inventory observations useful for a DPIA or records of processing.

## What NOT to report

- Strictly necessary cookies (session, CSRF, load balancer, consent state) as consent violations.
- Personal data that is necessary for the feature and protected appropriately.
- Legal conclusions ("this violates Article 6") — describe the engineering gap and the risk instead.
- Data in test fixtures or seed scripts with obviously fake values.`,
		RESPONSIBLE_USE,
		REPORTING,
	),
};
