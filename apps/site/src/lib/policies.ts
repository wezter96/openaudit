/**
 * Policies: the privacy policy, cookie policy and AI transparency notice, at
 * /<slug>/ (/privacy/, /cookies/, /ai/). Each is a Markdown file in
 * src/policies/ with the guides' front matter and house rules
 * (src/lib/guides.ts); `order` is their order in the footer and llms.txt.
 */
import { type Guide, loadPages } from "./guides";

export type Policy = Guide;

export const policies = loadPages("apps/site/src/policies");

export const policyPath = (slug: string) => `/${slug}/`;
