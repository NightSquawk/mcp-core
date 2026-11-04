#!/usr/bin/env node
/** The `mcp-guard` command. */
import { realIo } from "./io.js";
import { run } from "./run.js";

process.exitCode = await run(process.argv.slice(2), realIo());
