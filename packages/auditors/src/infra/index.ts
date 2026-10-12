import type { Auditor } from "@openaudit/core";

import { checkov } from "./checkov";
import { compose } from "./compose";
import { dockerfile } from "./dockerfile";
import { githubActions } from "./github-actions";
import { hadolint } from "./hadolint";
import { image } from "./image";
import { kubernetes } from "./kubernetes";
import { terraform } from "./terraform";

export const infraAuditors: ReadonlyArray<Auditor> = [
	dockerfile,
	compose,
	image,
	hadolint,
	githubActions,
	kubernetes,
	terraform,
	checkov,
];
