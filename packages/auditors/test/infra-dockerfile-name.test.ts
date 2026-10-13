import { describe, expect, test } from "bun:test";

import { DOCKERFILE_RE } from "../src/infra/dockerfile";

describe("DOCKERFILE_RE", () => {
	test("matches Dockerfile variants but not source files named after them", () => {
		for (const f of [
			"Dockerfile",
			"svc/Dockerfile.prod",
			"Containerfile",
			"x.dockerfile",
		])
			expect(DOCKERFILE_RE.test(f)).toBe(true);
		for (const f of [
			"src/infra/dockerfile.ts",
			"docs/Dockerfile.md",
			"Dockerfile.dockerignore",
			"lib/containerfile.py",
		])
			expect(DOCKERFILE_RE.test(f)).toBe(false);
	});
});
