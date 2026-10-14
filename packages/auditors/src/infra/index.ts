import type { Auditor } from "@openaudit/core";

import { actionlint } from "./actionlint";
import { checkov } from "./checkov";
import { compose } from "./compose";
import { dockerfile } from "./dockerfile";
import { dockle } from "./dockle";
import { githubActions } from "./github-actions";
import { hadolint } from "./hadolint";
import { image } from "./image";
import { kics } from "./kics";
import { kubeLinter } from "./kube-linter";
import { kubeconform } from "./kubeconform";
import { kubernetes } from "./kubernetes";
import { kubescape } from "./kubescape";
import { terraform } from "./terraform";
import { tflint } from "./tflint";
import { zizmor } from "./zizmor";

export const infraAuditors: ReadonlyArray<Auditor> = [
	dockerfile,
	compose,
	image,
	hadolint,
	dockle,
	githubActions,
	zizmor,
	actionlint,
	kubernetes,
	kubeLinter,
	kubescape,
	kubeconform,
	terraform,
	tflint,
	checkov,
	kics,
];
