import { describe, expect, test } from "bun:test";

import { auditTerraform, parseBlocks, terraform } from "../src/infra/terraform";
import { fixture, ruleIds, runAuditor } from "./helpers";

const ids = (text: string) =>
	auditTerraform("main.tf", text).map((f) => f.ruleId);

describe("iac.terraform", () => {
	test("flags misconfigurations and committed state", async () => {
		const report = await runAuditor(
			terraform,
			fixture("infra", "terraform-bad"),
		);
		expect(report.results[0]?.status).toBe("failed");
		expect(ruleIds(report)).toEqual([
			"iac.terraform/azure-blob-public",
			"iac.terraform/db-publicly-accessible",
			"iac.terraform/gcs-public",
			"iac.terraform/hardcoded-password",
			"iac.terraform/hardcoded-provider-credentials",
			"iac.terraform/hardcoded-provider-credentials",
			"iac.terraform/iam-wildcard-policy",
			"iac.terraform/logging-disabled",
			"iac.terraform/rds-unencrypted",
			"iac.terraform/s3-public-access-block-missing",
			"iac.terraform/s3-public-acl",
			"iac.terraform/security-group-open",
			"iac.terraform/state-committed",
			"iac.terraform/storage-unencrypted",
		]);
		const findings = report.results[0]?.findings ?? [];
		const find = (id: string) =>
			findings.find((f) => f.ruleId === `iac.terraform/${id}`);
		expect(find("state-committed")?.severity).toBe("critical");
		expect(find("state-committed")?.location?.file).toBe("terraform.tfstate");
		expect(find("security-group-open")?.location?.line).toBe(15);
		expect(find("iam-wildcard-policy")?.location?.line).toBe(51);
		for (const f of findings.filter((f) => f.ruleId.includes("hardcoded")))
			expect(f.evidence).toContain("****");
	});

	test("passes a secure configuration", async () => {
		const report = await runAuditor(
			terraform,
			fixture("infra", "terraform-clean"),
		);
		expect(report.results[0]?.status).toBe("passed");
		expect(ruleIds(report)).toEqual([]);
	});

	test("parses nested blocks and ignores braces in strings and heredocs", () => {
		const blocks = parseBlocks(
			[
				'resource "a" "b" {',
				'  x = "}"',
				"  y = <<EOT",
				"  }}}",
				"EOT",
				"  nested {",
				"    z = 1",
				"  }",
				"}",
				'provider "aws" {}',
			].join("\n"),
		);
		expect(blocks.map((b) => [b.keyword, b.labels, b.line])).toEqual([
			["resource", ["a", "b"], 1],
			["provider", ["aws"], 10],
		]);
	});

	test("handles rule-style and other-cloud firewall resources", () => {
		expect(
			ids(`resource "aws_security_group_rule" "all" {
  type        = "ingress"
  protocol    = "-1"
  from_port   = 0
  to_port     = 0
  cidr_blocks = ["0.0.0.0/0"]
}`),
		).toEqual(["iac.terraform/security-group-open"]);
		expect(
			ids(`resource "aws_vpc_security_group_ingress_rule" "rdp" {
  cidr_ipv6   = "::/0"
  ip_protocol = "tcp"
  from_port   = 3389
  to_port     = 3389
}`),
		).toEqual(["iac.terraform/security-group-open"]);
		expect(
			ids(`resource "google_compute_firewall" "ssh" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}`),
		).toEqual(["iac.terraform/firewall-open"]);
		expect(
			ids(`resource "azurerm_network_security_group" "nsg" {
  security_rule {
    direction                  = "Inbound"
    access                     = "Allow"
    source_address_prefix      = "*"
    destination_port_range     = "3389"
  }
}`),
		).toEqual(["iac.terraform/nsg-open"]);
	});

	test("does not treat variable references as hardcoded credentials", () => {
		expect(
			ids(`provider "aws" {
  access_key = var.access_key
  secret_key = "\${var.secret}"
}`),
		).toEqual([]);
	});
});
