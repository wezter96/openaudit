import type { RouterClient } from "@orpc/server";
import { z } from "zod";

import { publicProcedure } from "../index";
import { auditRouter } from "./audit";
import { auditorsRouter, playbooksRouter } from "./catalog";

export const appRouter = {
	healthCheck: publicProcedure
		.route({ method: "GET", path: "/healthCheck", tags: ["Meta"] })
		.output(z.string())
		.handler(() => {
			return "OK";
		}),
	auditors: auditorsRouter,
	playbooks: playbooksRouter,
	audit: auditRouter,
};
export type AppRouter = typeof appRouter;
export type AppRouterClient = RouterClient<typeof appRouter>;
