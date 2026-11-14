# uBlock Origin resources

The scriptlets are vendored from **uBlock Origin 1.76.2**, commit
[`e25a1b3b9e0a9c8db345453f1b8a0a9d109668b7`](https://github.com/gorhill/uBlock/tree/e25a1b3b9e0a9c8db345453f1b8a0a9d109668b7).

- `scriptlet-resources/` is an unmodified copy of upstream `src/js/resources/`.
- `arglist-parser.js`, `jsonpath.js`, and `urlskip.js` are unmodified copies from
  upstream `src/js/`, required by those modules.
- `SCRIPTLETS-LICENSE.txt` is upstream's GPL-3.0 license. Individual source files
  retain their copyright and license notices.
- `scriptlets.js` is Privaxy's stable entry point; `package.json` enables ES modules
  for Node during preprocessing. Neither file is injected into proxied pages.

To update, copy these modules and dependencies from one pinned upstream commit,
preserve the license, and update this provenance. From `privaxy/`, run:

```sh
mkdir -p prebuilt
node build-scriptlets.mjs src/resources/vendor/ublock/scriptlets.js prebuilt/scriptlets-resources.json
```

The generated resource JSON is a build artifact. Normal Cargo builds generate it
automatically; CI supplies it to cross-build containers without Node. The
converter preserves dependency names and `requiresTrust` metadata and uses
adblock-rust's function calling convention, including all filter arguments.

The older `redirect-resources.js` and `web_accessible_resources/` remain separate
redirect resources; they are not part of the scriptlet version pin above.
