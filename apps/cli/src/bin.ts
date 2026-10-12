#!/usr/bin/env bun
import { main } from "./main";

const code = await main(process.argv.slice(2));
// -1: a long-running command (the MCP server) owns the process lifetime.
if (code >= 0) process.exitCode = code;
