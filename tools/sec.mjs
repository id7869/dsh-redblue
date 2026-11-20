#!/usr/bin/env node
// dsh-redblue zero-dependency tool runtime entry point.
// See docs/tool-runtime.md and `node tools/sec.mjs --help`.

import { runCli } from "./lib/cli.mjs";

process.exitCode = await runCli(process.argv.slice(2));