import type { Playbook } from "../playbook";
import { compose, REPORTING, RESPONSIBLE_USE } from "./shared";

export const a11yJourneys: Playbook = {
	id: "agent.a11y-journeys",
	title: "Accessibility journeys (keyboard & screen reader)",
	summary:
		"Walks key user journeys keyboard-only and through the accessibility tree to find what automated checkers like axe cannot: focus management, dialogs, errors, live regions, reflow, zoom and motion.",
	categories: ["accessibility"],
	targets: ["webapp", "url"],
	needs: ["browser", "network"],
	checklist: [
		"Identified 3–5 key journeys (navigation, search, sign-in/sign-up, primary form or checkout, a dialog/menu flow)",
		"Completed each journey keyboard-only: everything reachable and operable with Tab/Shift+Tab/Enter/Space/Escape/arrow keys",
		"Checked focus visibility on every interactive element and that focus order matches visual/logical order",
		"Checked skip link / landmarks / heading structure for efficient navigation",
		"Checked dialogs/menus/popovers: focus moves in, is contained, Escape closes, focus returns to the trigger",
		"Checked forms: programmatic labels, required/invalid state, error messages associated with fields and announced, focus moved to errors on submit",
		"Checked dynamic updates are announced (live regions/status messages for toasts, search results, cart updates, loading states)",
		"Checked accessible names/roles/states of custom controls (buttons, toggles, tabs, comboboxes, accordions) in the accessibility tree",
		"Checked reflow at 320 CSS px width and zoom/text resize to 200% without loss of content or function",
		"Checked prefers-reduced-motion is respected and nothing auto-plays/flashes without controls",
		"Checked route changes in single-page apps move focus or announce the new page and update the document title",
	],
	instructions: compose(
		`# Accessibility journeys (keyboard & screen reader)

## Scope

A running website or web app (WCAG 2.2 AA as the yardstick). Automated rule engines (openaudit \`web.a11y\`, axe, Lighthouse) already catch static issues such as missing alt text, contrast and missing labels on simple inputs. Your job is the **interactive** behaviour they cannot judge: can a keyboard-only or screen-reader user actually complete the important tasks?

## Tools

- **With a browser (Playwright or similar):** use real key presses (Tab, Shift+Tab, Enter, Space, Escape, arrow keys), read the accessibility tree / snapshot after each step to see the focused element, its role, name and state, and resize the viewport for reflow checks. Use the browser's media emulation for \`prefers-reduced-motion\` when available.
- **Without a browser:** you can only review the served HTML (and source code if available). Report what the markup proves (e.g. a dialog with no focus management code, \`div\` buttons without roles/tabindex, missing live regions) and clearly state that journeys were **not** exercised interactively.

## Method

1. **Pick journeys.** From the home page and navigation, choose 3–5 representative journeys: primary navigation (including mobile menu), search, sign-in or sign-up (with the provided test account only), the main form or conversion flow, and at least one dialog/menu/disclosure. Stay on the target origin.
2. **Keyboard-only walkthrough.** For each journey, start from the top of the page and Tab through. At each step record: what has focus, whether the focus indicator is visible, whether the order makes sense, and whether the control works with the expected keys (Enter for links/buttons, Space for buttons/checkboxes, arrows inside menus/tabs/radios/listboxes, Escape to close). Note keyboard traps and elements that are clickable but not focusable.
3. **Accessibility tree.** For custom widgets, check role, accessible name and state (\`aria-expanded\`, \`aria-selected\`, \`aria-checked\`, \`aria-pressed\`, \`aria-current\`, \`aria-invalid\`) and that the state updates when you operate the widget. Icon-only buttons need names. Check heading outline and landmarks (one \`main\`, labelled \`nav\`s) and that a skip link exists and works on pages with repeated navigation.
4. **Dialogs and overlays.** On open, focus moves into the dialog (to the first meaningful element or the dialog itself); Tab stays inside a modal; background content is inert (\`aria-modal\`/\`inert\`); Escape closes; on close, focus returns to the element that opened it. Cookie banners and toasts must not trap or steal focus unexpectedly.
5. **Forms and errors.** Submit forms empty or with an obviously invalid value (no real personal data). Check that each field has a programmatic label, that required fields are indicated in text and programmatically, that errors are shown in text (not colour only), associated with the field (\`aria-describedby\`), announced (live region or focus moved to an error summary or the first invalid field), and that input is preserved.
6. **Dynamic content.** Trigger updates (search results, filters, add-to-cart, async save, loading spinners, toasts). Confirm a status message is exposed via \`role="status"\`/\`aria-live\` or focus management. In SPAs, navigate between routes and check that focus moves to the new content or heading and \`document.title\` changes.
7. **Reflow, zoom and text spacing.** Set the viewport to 320×800 CSS px and check content reflows without two-dimensional scrolling or clipped/overlapping content (except maps, tables, diagrams). Check that 200% zoom (or 640 px wide at 2× scale) keeps all content and functions available and that fixed headers do not cover focused elements.
8. **Motion and media.** Check \`prefers-reduced-motion: reduce\` disables non-essential animation and parallax; auto-playing carousels/videos have pause controls; nothing flashes more than three times per second.
9. **Target size & pointer.** Spot-check small, tightly packed targets (< 24×24 CSS px) and drag-only interactions without alternatives.

## Severity rubric

- **critical** — a keyboard or screen-reader user cannot complete a primary journey (sign-in, checkout, main form): keyboard trap, unreachable submit, dialog that cannot be closed.
- **high** — serious barriers on key journeys: no visible focus, focus lost to \`body\` after dialogs/route changes, errors not announced or not associated, custom controls with no role/name/state, content lost at 320 px or 200% zoom.
- **medium** — barriers with workarounds or on secondary flows: illogical focus order, missing skip link on heavy navigation, status updates not announced, motion not reduced.
- **low** — minor issues: redundant or verbose names, small targets with adequate spacing, inconsistent headings.
- **info** — good practices worth noting, or areas you could not test.

Map each finding to the relevant WCAG 2.2 success criterion in \`references\` (e.g. https://www.w3.org/WAI/WCAG22/Understanding/focus-order) and add the SC number to the message.

## What NOT to report

- Issues already detectable by axe (contrast ratios, missing alt text, empty links) unless they block a journey — rule engines cover those.
- Personal preferences about design that do not map to a WCAG criterion or a concrete barrier.
- Behaviour you inferred but did not observe — say "not tested" in your coverage notes instead.`,
		RESPONSIBLE_USE,
		REPORTING,
	),
};
