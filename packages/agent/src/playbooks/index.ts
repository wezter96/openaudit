import type { Playbook } from "../playbook";
import { a11yJourneys } from "./a11y-journeys";
import { authz } from "./authz";
import { iacArchitecture } from "./iac-architecture";
import { injection } from "./injection";
import { mobile } from "./mobile";
import { performance } from "./performance";
import { privacy } from "./privacy";
import { secretsConfig } from "./secrets-config";
import { uxContent } from "./ux-content";
import { webappSecurity } from "./webapp-security";

export const playbooks: ReadonlyArray<Playbook> = [
	authz,
	injection,
	secretsConfig,
	performance,
	privacy,
	a11yJourneys,
	webappSecurity,
	uxContent,
	mobile,
	iacArchitecture,
];

export {
	a11yJourneys,
	authz,
	iacArchitecture,
	injection,
	mobile,
	performance,
	privacy,
	secretsConfig,
	uxContent,
	webappSecurity,
};
