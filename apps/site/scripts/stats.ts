/**
 * Page views on openaudit.se from the anonymous counter in worker/visits.ts.
 *
 * Usage: bun scripts/stats.ts [days]   (default 7)
 *
 * Needs CLOUDFLARE_ACCOUNT_ID and a CLOUDFLARE_API_TOKEN with the
 * "Account Analytics: Read" permission (Cloudflare dashboard → My Profile →
 * API Tokens → Create Token → Custom token).
 *
 * These are page views, not people: nothing the counter stores can tell two
 * visits by the same person apart.
 */
export {};

const DATASET = "openaudit_site_visits";
const days = Math.max(1, Math.min(90, Number(process.argv[2] ?? 7) || 7));
const account = process.env.CLOUDFLARE_ACCOUNT_ID;
const token = process.env.CLOUDFLARE_API_TOKEN;
if (!account || !token) {
	console.error(
		"stats: set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN (with Account Analytics: Read).",
	);
	process.exit(1);
}

type Row = Record<string, string | number>;
const sql = async (query: string): Promise<Row[]> => {
	const res = await fetch(
		`https://api.cloudflare.com/client/v4/accounts/${account}/analytics_engine/sql`,
		{
			method: "POST",
			headers: { Authorization: `Bearer ${token}` },
			body: query,
		},
	);
	const text = await res.text();
	if (!res.ok) throw new Error(`Analytics Engine ${res.status}: ${text}`);
	return (JSON.parse(text) as { data: Row[] }).data;
};

const since = `timestamp > NOW() - INTERVAL '${days}' DAY`;
const humans = `${since} AND blob3 = 'human' AND blob2 = 'page'`;
const views = "SUM(_sample_interval) AS views";
const ranked = (column: string, where: string, limit = 10) =>
	sql(
		`SELECT ${column} AS key, ${views} FROM ${DATASET} WHERE ${where} GROUP BY key ORDER BY views DESC LIMIT ${limit}`,
	);

const [daily, pages, referrers, countries, devices, kinds, bots] =
	await Promise.all([
		sql(
			`SELECT toStartOfInterval(timestamp, INTERVAL '1' DAY) AS key, ${views} FROM ${DATASET} WHERE ${humans} GROUP BY key ORDER BY key`,
		),
		ranked("blob1", humans, 15),
		ranked("blob5", `${humans} AND blob5 != ''`),
		ranked("blob6", humans),
		ranked("blob7", humans),
		ranked("concat(blob3, ' ', blob2)", since),
		ranked("blob4", `${since} AND blob3 = 'bot'`, 15),
	]);

const table = (title: string, rows: Row[], label = (k: string) => k) => {
	console.log(`\n${title}`);
	if (!rows.length) {
		console.log("  (none)");
		return;
	}
	const width = Math.max(...rows.map((r) => label(String(r.key)).length));
	for (const r of rows) {
		console.log(
			`  ${label(String(r.key)).padEnd(width)}  ${String(Math.round(Number(r.views))).padStart(7)}`,
		);
	}
};

console.log(`openaudit.se, last ${days} day(s). Page views, not people.`);
table("Human page views per day", daily, (k) => k.slice(0, 10));
table("Top pages", pages);
table("Top referrers", referrers);
table("Countries", countries);
table("Devices", devices);
table("All views by who and kind", kinds);
table("Bots and agents", bots);
