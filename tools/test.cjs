"use strict";
// Expand test files without relying on shell glob support (including Windows).
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const root = path.resolve(__dirname, "..");
const tests = fs
  .readdirSync(path.join(root, "tests"))
  .filter((name) => name.endsWith(".test.js"))
  .sort()
  .map((name) => path.join(root, "tests", name));
const result = spawnSync(process.execPath, ["--test", ...tests], { stdio: "inherit" });
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
