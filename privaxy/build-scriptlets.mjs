// Compiles uBlock Origin's modern `scriptlets.js` (the
// `builtinScriptlets.push({ name, fn, dependencies, ... })` format) into the
// JSON Resource schema expected by adblock-rust's `Engine::use_resources`.
//
// Strategy lifted from brave/brave-core-crx-packager `lib/adBlockRustUtils.js`
// (MPL-2.0): walk each scriptlet's transitive `dependencies`, inline the
// dependency function source as a prelude, then wrap the scriptlet body in a
// shim that exposes the legacy numbered template args `{{1}}`..`{{9}}`. The
// `as_css` / numbered-arg style is what adblock-rust's templating layer
// understands; the new format's positional `fn(...args)` calling convention
// is bridged inside the shim.
//
// Invoked from build.rs as `node build-scriptlets.mjs <scriptlets.js> <out.json>`.

import { promises as fs } from 'fs';
import os from 'os';
import path from 'path';
import { pathToFileURL } from 'url';

const [, , scriptletsPath, outPath] = process.argv;
if (!scriptletsPath || !outPath) {
    console.error('usage: node build-scriptlets.mjs <scriptlets.js> <out.json>');
    process.exit(2);
}

const wrap = (fnString, dependencyPrelude) => `{
  const args = ["{{1}}", "{{2}}", "{{3}}", "{{4}}", "{{5}}", "{{6}}", "{{7}}", "{{8}}", "{{9}}"];
  let last_arg_index = 0;
  for (const arg_index in args) {
    if (args[arg_index] === '{{' + (Number(arg_index) + 1) + '}}') {
      break;
    }
    last_arg_index += 1;
  }
  ${dependencyPrelude}
  (${fnString})(...args.slice(0, last_arg_index))
}`;

// scriptlets.js is plain ESM but lives under a `.js` extension in the vendor
// dir. Node only treats `.js` as ESM with a sibling `package.json` declaring
// `"type": "module"`, which we don't want to add. Copy to a `.mjs` in a
// scratch dir so dynamic import resolves it unambiguously as ESM.
const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'privaxy-scriptlets-'));
const tmpFile = path.join(tmpDir, 'scriptlets.mjs');
try {
    await fs.writeFile(tmpFile, await fs.readFile(scriptletsPath, 'utf8'));
    const { builtinScriptlets } = await import(pathToFileURL(tmpFile).href);

    const byName = new Map(builtinScriptlets.map((e) => [e.name, e]));

    const resources = builtinScriptlets
        // `.fn`-suffixed entries are pure dependency helpers (e.g. `safe-self.fn`),
        // not user-invocable scriptlets.
        .filter((s) => !s.name.endsWith('.fn'))
        .map((s) => {
            const deps = [...(s.dependencies ?? [])];
            for (const d of deps) {
                for (const rd of byName.get(d)?.dependencies ?? []) {
                    if (!deps.includes(rd)) deps.push(rd);
                }
            }
            let prelude = '';
            // Reverse so leaf dependencies are declared before their consumers.
            for (const d of deps.reverse()) {
                const entry = byName.get(d);
                if (!entry) throw new Error(`Missing dependency: ${d} (referenced by ${s.name})`);
                prelude += entry.fn.toString() + '\n';
            }
            const content = Buffer.from(wrap(s.fn.toString(), prelude)).toString('base64');
            return {
                name: s.name,
                aliases: s.aliases ?? [],
                kind: { mime: 'application/javascript' },
                content,
            };
        });

    await fs.writeFile(outPath, JSON.stringify(resources));
} finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
}
