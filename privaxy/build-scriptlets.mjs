// Convert the pinned uBlock Origin modules into adblock-rust resources.
// Keep functions and dependency helpers separate: the engine deduplicates them
// and calls each scriptlet with its complete, safely quoted argument list.
// Usage: node build-scriptlets.mjs <scriptlets.js> <out.json>
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [, , scriptletsPath, outPath] = process.argv;
if (!scriptletsPath || !outPath) {
    throw new Error('usage: node build-scriptlets.mjs <scriptlets.js> <out.json>');
}

const { builtinScriptlets } = await import(pathToFileURL(path.resolve(scriptletsPath)).href);
const byName = new Map(builtinScriptlets.map(entry => [entry.name, entry]));
if (byName.size !== builtinScriptlets.length) {
    throw new Error('Duplicate scriptlet resource name');
}

const resources = builtinScriptlets.map(entry => {
    const source = entry.fn.toString();
    if (!entry.name.endsWith('.fn') && !/^function\s+\w+\s*\(/.test(source)) {
        throw new Error(`Scriptlet ${entry.name} must be a named function`);
    }
    for (const dependency of entry.dependencies ?? []) {
        if (!byName.has(dependency)) {
            throw new Error(`Missing dependency ${dependency} for ${entry.name}`);
        }
    }
    return {
        name: entry.name,
        aliases: entry.aliases ?? [],
        kind: { mime: 'application/javascript' },
        content: Buffer.from(source).toString('base64'),
        dependencies: entry.dependencies ?? [],
        // Must agree with TRUSTED_SCRIPTLETS in server/filter_list.rs.
        permission: entry.requiresTrust ? 1 : 0,
    };
});
await fs.writeFile(outPath, JSON.stringify(resources));
