import { agenticAuditors, playbooks } from "@openaudit/agent";
import { builtinAuditors } from "@openaudit/auditors";
import type { Auditor } from "@openaudit/core";
import { ORPCError } from "@orpc/server";
import { z } from "zod";

import { publicProcedure } from "../index";
import {
	AuditorInfoSchema,
	PlaybookSchema,
	PlaybookSummarySchema,
} from "../schemas";

const toInfo = (a: Auditor): z.infer<typeof AuditorInfoSchema> => ({
	id: a.id,
	title: a.title,
	description: a.description,
	engine: a.engine,
	categories: [...a.categories],
	targets: [...a.targets],
	tool: a.tool,
	network: a.network ?? false,
	defaultEnabled: a.engine === "agentic" ? false : a.defaultEnabled !== false,
});

export const auditorsRouter = {
	list: publicProcedure
		.route({
			method: "GET",
			path: "/auditors",
			summary: "List auditors",
			description:
				"Built-in, external-tool and agentic auditors with the categories and target kinds they cover.",
			tags: ["Catalog"],
		})
		.output(z.array(AuditorInfoSchema))
		.handler(() => [...builtinAuditors, ...agenticAuditors].map(toInfo)),
};

export const playbooksRouter = {
	list: publicProcedure
		.route({
			method: "GET",
			path: "/playbooks",
			summary: "List playbooks",
			description:
				"Judgment-heavy audit procedures that agents execute (via MCP or the agentic auditors).",
			tags: ["Catalog"],
		})
		.output(z.array(PlaybookSummarySchema))
		.handler(() =>
			playbooks.map(({ instructions: _, ...p }) => ({
				...p,
				categories: [...p.categories],
				targets: [...p.targets],
				needs: [...p.needs],
				checklist: [...p.checklist],
			})),
		),

	get: publicProcedure
		.route({
			method: "GET",
			path: "/playbooks/{id}",
			summary: "Get a playbook",
			description: "A playbook including its full Markdown instructions.",
			tags: ["Catalog"],
		})
		.input(z.object({ id: z.string().min(1).max(100) }))
		.output(PlaybookSchema)
		.handler(({ input }) => {
			const p = playbooks.find((p) => p.id === input.id);
			if (!p)
				throw new ORPCError("NOT_FOUND", {
					message: `No playbook with id "${input.id}"`,
				});
			return {
				...p,
				categories: [...p.categories],
				targets: [...p.targets],
				needs: [...p.needs],
				checklist: [...p.checklist],
			};
		}),
};
