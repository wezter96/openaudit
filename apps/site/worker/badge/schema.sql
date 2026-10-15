-- D1 schema for the verified badges (database openaudit-badges, binding BADGES).
-- Apply with:
--   bunx wrangler d1 execute openaudit-badges --remote --file worker/badge/schema.sql
-- Times are Unix seconds.

CREATE TABLE IF NOT EXISTS projects (
	id TEXT PRIMARY KEY,
	repo TEXT NOT NULL UNIQUE COLLATE NOCASE,
	site TEXT,
	code TEXT NOT NULL,
	-- SHA-256 (hex) of the manage token; the token itself is never stored.
	manage_hash TEXT NOT NULL,
	-- pending, active or removed (a tombstone, so the badge can say so).
	status TEXT NOT NULL,
	repo_verified INT NOT NULL DEFAULT 0,
	site_verified INT NOT NULL DEFAULT 0,
	created_at INT NOT NULL,
	next_scan_at INT,
	last_rescan_at INT,
	-- Daily-salted hash of the registering IP, never the IP.
	ip_day TEXT,
	-- Last ownership check, so /verify can't be used to hammer a site.
	checked_at INT
);

CREATE INDEX IF NOT EXISTS projects_due ON projects (status, next_scan_at);

CREATE TABLE IF NOT EXISTS scans (
	id TEXT PRIMARY KEY,
	project_id TEXT NOT NULL,
	-- running, ok or failed.
	status TEXT NOT NULL,
	started_at INT NOT NULL,
	finished_at INT,
	lease_until INT,
	commit_sha TEXT,
	openaudit_version TEXT,
	codebase_summary TEXT,
	site_summary TEXT,
	error TEXT
);

CREATE INDEX IF NOT EXISTS scans_project ON scans (project_id, started_at);
CREATE INDEX IF NOT EXISTS scans_lease ON scans (status, lease_until);

CREATE TABLE IF NOT EXISTS registrations (
	ip_day_hash TEXT NOT NULL,
	created_at INT NOT NULL
);

CREATE INDEX IF NOT EXISTS registrations_ip ON registrations (ip_day_hash, created_at);
