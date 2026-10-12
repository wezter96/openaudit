import type { Playbook } from "../playbook";
import { compose, REPORTING, RESPONSIBLE_USE } from "./shared";

export const uxContent: Playbook = {
	id: "agent.ux-content",
	title: "UX, content & SEO quality review",
	summary:
		"Judges what metrics cannot: content quality and search intent, Nielsen usability heuristics, broken or confusing journeys, unclear copy and mobile layout problems.",
	categories: ["seo", "best-practices", "accessibility"],
	targets: ["url", "webapp"],
	needs: ["network"],
	checklist: [
		"Identified the site's purpose, audience and primary conversion(s)",
		"Reviewed key pages' titles, meta descriptions, H1s and copy against the search intent they target; flagged thin, duplicate or keyword-stuffed content",
		"Checked internal linking, navigation labels and information architecture for findability",
		"Walked the primary journey(s) end to end (without submitting real data) and noted broken steps, dead ends and confusing transitions",
		"Evaluated against Nielsen's 10 heuristics with concrete examples",
		"Reviewed copy for clarity, jargon, inconsistent terminology, unclear calls to action and error messages",
		"Checked mobile layout (≈375 px width): overflow, overlapping elements, tiny tap targets, intrusive interstitials",
		"Checked trust signals and E-E-A-T basics: contact info, about page, authorship, dates on time-sensitive content, policies",
		"Checked structured data / rich-result eligibility on key templates matches visible content",
		"Checked empty states, 404 page and search no-results experience",
	],
	instructions: compose(
		`# UX, content & SEO quality review

## Scope

A public website or web app, reviewed as a careful expert user and an SEO editor would. Deterministic auditors already check technical SEO signals (status codes, canonical tags, robots, sitemaps, meta tag presence, Core Web Vitals). Focus on **quality and judgment**: is the content good, is the site understandable and usable, do journeys work?

Fetch pages with the tools you have (browser if available, otherwise page fetches). Review roughly 5–15 representative pages: home, main category/listing, a detail/product/article page, pricing or conversion page, about/contact, search, 404. Stay on the target origin.

## Method

1. **Purpose and audience.** From the home page, state in one sentence what the site offers, to whom, and the primary action it wants visitors to take. If you cannot tell within a few seconds of reading, that is itself a finding.
2. **Content and search intent.** For each key page: does the \`<title>\`/H1/intro match the query a searcher would use to land there? Is the content substantive, original and specific (not thin, templated or duplicated across pages)? Are headings descriptive? Is time-sensitive content dated? Are there obvious keyword-stuffing or doorway-page patterns?
3. **Findability.** Navigation labels that users would understand, logical grouping, breadcrumbs on deep hierarchies, internal links between related content, orphaned-looking key pages, search that works.
4. **Journeys.** Walk the primary journey(s): discover → evaluate → act (sign up, contact, buy, download). Do not submit forms with real personal data or complete purchases. Note broken links/buttons, dead ends, steps that lose state, unexpected redirects, forms that ask for too much, and unclear next steps.
5. **Heuristic evaluation (Nielsen).** Visibility of system status; match with the real world; user control and freedom; consistency and standards; error prevention; recognition rather than recall; flexibility and efficiency; aesthetic and minimalist design; help users recognise, diagnose and recover from errors; help and documentation. Report only concrete violations with a page and element.
6. **Copy.** Clear value proposition, plain language, consistent terminology, specific CTAs ("Start free trial" vs "Submit"), helpful error and empty-state messages, no lorem ipsum or placeholder text, spelling errors on key pages.
7. **Mobile layout.** At ≈375 px width (browser) or by reading responsive CSS/markup: horizontal overflow, overlapping or clipped content, fixed elements covering content, tap targets too small or too close, intrusive pop-ups on entry.
8. **Trust.** Contact details, company/about information, author bylines and credentials on advice content, privacy policy and terms linked, secure checkout cues, reviews/testimonials that look genuine.
9. **Structured data.** On key templates, check that JSON-LD types fit the content (Product, Article, Organization, BreadcrumbList, FAQ only where visible) and match visible values.
10. **Edge states.** Helpful 404 page with navigation, search no-results guidance, empty states that explain what to do.

## Severity rubric

- **high** — primary journey broken or blocked (dead CTA, form that cannot be submitted, checkout dead end), key landing pages with no meaningful content or wrong/duplicate titles site-wide, mobile layout that hides primary actions.
- **medium** — significant friction or confusion on key journeys, thin/duplicate content on important templates, misleading copy, missing trust information for transactional sites, structured data that misrepresents content.
- **low** — minor copy and consistency issues, small layout glitches, secondary-page content gaps.
- **info** — improvement ideas grounded in an observation.

Use \`category: "seo"\` for search/content findings, \`"best-practices"\` for UX/copy, \`"accessibility"\` only where the problem is an accessibility barrier.

## What NOT to report

- Subjective visual taste ("I would use a different colour") without a usability consequence.
- Technical SEO checks deterministic auditors already make (missing meta description tag, canonical, robots, sitemap) unless the content of those tags is wrong.
- Generic advice ("add more content", "improve SEO") without a specific page and a specific change.`,
		RESPONSIBLE_USE,
		REPORTING,
	),
};
