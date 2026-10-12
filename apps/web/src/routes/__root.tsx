import { Toaster } from "@openaudit/ui/components/sonner";
import type { QueryClient } from "@tanstack/react-query";
import {
	createRootRouteWithContext,
	HeadContent,
	Outlet,
	ScriptOnce,
	Scripts,
} from "@tanstack/react-router";
import { lazy, Suspense } from "react";

import type { orpc } from "@/utils/orpc";

import Footer from "../components/footer";
import Header from "../components/header";
import { themeScript } from "../components/theme-toggle";
import appCss from "../index.css?url";

const Devtools = import.meta.env.DEV
	? lazy(async () => {
			const [{ TanStackRouterDevtools }, { ReactQueryDevtools }] =
				await Promise.all([
					import("@tanstack/react-router-devtools"),
					import("@tanstack/react-query-devtools"),
				]);
			return {
				default: () => (
					<>
						<TanStackRouterDevtools position="bottom-left" />
						<ReactQueryDevtools buttonPosition="bottom-right" />
					</>
				),
			};
		})
	: () => null;

export interface RouterAppContext {
	orpc: typeof orpc;
	queryClient: QueryClient;
}

export const Route = createRootRouteWithContext<RouterAppContext>()({
	head: () => ({
		meta: [
			{ charSet: "utf-8" },
			{ name: "viewport", content: "width=device-width, initial-scale=1" },
			{ title: "openaudit: audit everything you ship" },
			{
				name: "description",
				content:
					"Audit code, sites, apps, containers, infrastructure and mobile builds for security, accessibility, performance, SEO, privacy and supply-chain issues, from your terminal or your AI agent.",
			},
			{ name: "color-scheme", content: "light dark" },
			{
				name: "theme-color",
				content: "#f4f6f9",
				media: "(prefers-color-scheme: light)",
			},
			{
				name: "theme-color",
				content: "#0e1726",
				media: "(prefers-color-scheme: dark)",
			},
		],
		links: [
			{ rel: "stylesheet", href: appCss },
			{ rel: "icon", href: "/favicon.svg", type: "image/svg+xml" },
		],
	}),
	component: RootDocument,
});

function RootDocument() {
	return (
		<html lang="en" suppressHydrationWarning>
			<head>
				<HeadContent />
			</head>
			<body>
				<ScriptOnce>{themeScript}</ScriptOnce>
				<a href="#main" className="skip-link">
					Skip to content
				</a>
				<div className="flex min-h-svh flex-col">
					<Header />
					<main id="main" tabIndex={-1} className="flex-1 focus:outline-none">
						<Outlet />
					</main>
					<Footer />
				</div>
				<Toaster richColors />
				<Suspense>
					<Devtools />
				</Suspense>
				<Scripts />
			</body>
		</html>
	);
}
