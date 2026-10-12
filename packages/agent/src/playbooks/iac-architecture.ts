import type { Playbook } from "../playbook";
import { compose, REPORTING } from "./shared";

export const iacArchitecture: Playbook = {
	id: "agent.iac-architecture",
	title: "Infrastructure architecture review",
	summary:
		"Reviews infrastructure-as-code and container definitions as a system: blast radius, least privilege, network segmentation, backup/DR, secrets management and supply chain of images and CI actions.",
	categories: ["security", "reliability", "supply-chain"],
	targets: ["iac", "container"],
	needs: ["code"],
	checklist: [
		"Built a picture of the architecture: environments, accounts/projects, networks, compute, data stores, ingress/egress, CI/CD deploy path",
		"Assessed blast radius: shared accounts/projects/clusters between environments, single credentials with broad reach, cross-environment trust",
		"Reviewed IAM/RBAC for least privilege: wildcard actions/resources, admin roles on workloads, long-lived keys, CI deploy role scope",
		"Reviewed network segmentation: public subnets/IPs, security groups/firewalls open to 0.0.0.0/0, databases reachable from the internet, Kubernetes NetworkPolicies",
		"Reviewed data stores: encryption at rest, public buckets/blobs, deletion protection, point-in-time recovery, backup retention and cross-region/account copies",
		"Reviewed availability/DR: single-AZ/region critical components, no health checks, no autoscaling limits, state stored on ephemeral disks",
		"Reviewed secrets management: secrets in state/variables/manifests vs a secret manager, rotation, workload identity",
		"Reviewed container definitions: base image provenance and pinning, root user, privileged/hostPath/hostNetwork, capabilities, read-only root filesystem, resource limits",
		"Reviewed supply chain: unpinned base images, third-party CI actions not pinned to SHAs, Terraform module/provider version pinning, Helm chart sources",
		"Reviewed logging/monitoring/audit trail: CloudTrail/audit logs, flow logs, alerting on critical resources",
		"Reviewed Terraform state handling: remote backend, encryption, locking, access",
	],
	instructions: compose(
		`# Infrastructure architecture review

## Scope

Infrastructure-as-code and deployment definitions: Terraform/OpenTofu, CloudFormation/CDK/Pulumi, Kubernetes manifests, Helm charts, Kustomize, Dockerfiles and compose files, and CI/CD workflows that deploy them. Deterministic scanners (Checkov, tfsec, Trivy, hadolint, openaudit infra auditors) flag single-resource misconfigurations. Your job is **system-level judgment**: how resources combine, what an attacker or an outage could reach from one compromised piece, and whether recovery is possible.

## Method

1. **Model the system.** Read the IaC to sketch environments (prod/staging/dev), accounts/projects/subscriptions, VPCs/subnets, clusters, compute (VMs, containers, functions), data stores, queues, ingress (load balancers, API gateways, CDNs) and egress, and how CI/CD deploys (which identity, which permissions). Write down the trust boundaries.
2. **Blast radius.** Look for shared accounts/projects/clusters/state between production and non-production, one IAM role or service account used by many workloads, CI credentials that can modify everything, cross-account trust policies with broad principals (\`"AWS": "*"\`, missing \`ExternalId\`/conditions), Kubernetes namespaces without isolation for multi-tenant workloads.
3. **Least privilege.** IAM policies with \`Action: "*"\`/\`Resource: "*"\` or service wildcards on workloads, \`iam:PassRole\` on \`*\`, admin managed policies on application roles, GCP primitive roles (\`roles/owner\`, \`roles/editor\`), Azure Owner/Contributor at subscription scope, Kubernetes \`cluster-admin\` bindings or wildcard RBAC, default service accounts with broad scopes, long-lived access keys instead of workload identity/OIDC.
4. **Network segmentation.** Security groups/firewall rules allowing \`0.0.0.0/0\` or \`::/0\` to admin ports (22, 3389) or databases (5432, 3306, 6379, 27017, 9200), data stores with public IPs or public network access, flat networks where everything can talk to everything, missing private endpoints for data stores, Kubernetes without NetworkPolicies for sensitive namespaces, services of type \`LoadBalancer\` unintentionally public.
5. **Data protection & recovery.** Encryption at rest and in transit on databases, buckets, disks and queues; public buckets/containers/blobs or ACLs; deletion protection and \`prevent_destroy\` on stateful resources; automated backups, point-in-time recovery, retention length, and copies in another account/region for ransomware/region-failure scenarios; object versioning/locking where data is critical.
6. **Availability.** Single-AZ databases and node groups for production, single replica deployments without PodDisruptionBudgets, missing health/readiness probes, no resource requests/limits, autoscaling without upper bounds (cost blowout) or without lower bounds (cold starts on critical paths).
7. **Secrets management.** Secrets in Terraform variables/defaults/outputs (they land in state), \`kubernetes_secret\` with literal data, Helm values with credentials, environment variables populated with literals in task definitions; prefer secret managers with rotation and workload identity.
8. **Containers.** Base images from unknown publishers, \`latest\` or floating tags without digest pinning, images running as root, \`privileged: true\`, \`hostPath\`/\`hostNetwork\`/\`hostPID\`, added capabilities (\`SYS_ADMIN\`, \`NET_ADMIN\`), writable root filesystems, Docker socket mounts, \`allowPrivilegeEscalation\` not disabled, missing \`seccompProfile\`.
9. **Supply chain.** Third-party GitHub Actions pinned by tag rather than commit SHA (especially in deploy workflows with cloud credentials), Terraform providers/modules without version constraints or from unverified sources, Helm charts from arbitrary repos, \`curl | sh\` in Dockerfiles/CI, no image signing/verification where the platform supports it.
10. **Observability & audit.** Cloud audit logs (CloudTrail, GCP audit logs, Azure activity logs) enabled and protected, VPC flow logs on sensitive networks, alerting on critical resources, log retention.
11. **State.** Terraform remote backend with encryption, locking and restricted access; no local state committed to the repository.

## Severity rubric

- **critical** — internet-exposed data stores or admin interfaces with weak/no auth, publicly readable buckets with sensitive data, workload or CI identity with account-wide admin reachable from untrusted input, committed state files with secrets.
- **high** — wildcard IAM on application workloads, production and non-production sharing credentials or clusters, privileged containers/host mounts, no backups or deletion protection on primary data stores, deploy workflows using unpinned third-party actions with cloud credentials.
- **medium** — missing network segmentation inside a VPC/cluster, single-AZ production data stores, images running as root, long-lived access keys, missing audit logs, floating image tags.
- **low** — hygiene: missing resource limits on non-critical workloads, tags-based pinning of trusted first-party actions, short log retention.
- **info** — architecture observations and recommendations without a concrete weakness.

## What NOT to report

- Single-resource misconfigurations already flagged by deterministic scanners, unless you add system-level impact (e.g. the open security group fronts the production database).
- Resources that are intentionally public (static website buckets, public load balancers for web apps, public container registries for open-source images).
- Development/sandbox-only stacks clearly separated from production, unless they hold production data or credentials.
- Cost optimisation unrelated to reliability or security.`,
		REPORTING,
	),
};
