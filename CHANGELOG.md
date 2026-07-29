# Changelog

## Unreleased

- Userscript engine: Greasemonkey/Tampermonkey-style scripts injected into
  matching pages, managed at runtime from the web UI.
  - New **Settings → Userscripts** page: install a script by pasting it or by
    URL (e.g. from Greasyfork), toggle scripts individually, edit a script's
    source in place, and uninstall it. A master switch disables the whole
    engine without clearing the per-script selection. Each entry shows its
    version, `@run-at`, match patterns, grant count and `@noframes` state, and
    a script whose stored body no longer parses is called out as not being
    injected instead of failing silently.
  - New `[userscripts]` configuration section holding the master `enabled` flag
    and one `[[userscripts.scripts]]` entry per script. As with filter lists,
    only metadata is stored in the configuration file; bodies live under
    `userscripts/` in the configuration directory (override with
    `PRIVAXY_USERSCRIPT_PATH`), keyed by a hash of the source URL so
    re-installing the same script reuses its file. Configurations written
    before this release parse unchanged and default to an enabled engine with
    no scripts.
  - Scripts are matched on the same canonical URL the adblock engine uses,
    supporting `@match` (Chrome match-pattern syntax including `<all_urls>` and
    `*.host` wildcards), `@include`/`@exclude` (globs, or regular expressions
    written `/…/`), `@exclude-match`, `@run-at`
    (`document-start`/`-body`/`-end`/`-idle`) and `@noframes`. Exclusions take
    precedence over inclusions. A script declaring neither `@match` nor
    `@include` — or with a malformed pattern or no metadata block — is rejected
    with a `422` at install time rather than being stored and never firing.
  - The in-page runtime provides `GM_info`, `unsafeWindow`, `GM_addStyle`
    (nonce-stamped so it survives the page's CSP), `GM_log`, `GM_openInTab`,
    `GM_setClipboard`, `GM_notification`, `GM_registerMenuCommand` and the
    promise-based `GM.*` namespace.
  - `@require` libraries and `@resource` payloads are fetched server-side and
    cached on disk under `userscripts/assets/`, keyed by URL hash. Requires are
    evaluated inside the script's own wrapper ahead of its body, so their
    top-level declarations are visible to the script without leaking into the
    page, and `GM_getResourceText`/`GM_getResourceURL` read the fetched
    resources. Cached assets are never re-fetched (the convention is to pin a
    versioned URL); delete the `assets` directory to refresh. An asset that
    cannot be fetched degrades its script rather than dropping it, and the
    failure is reported on the Userscripts page.
  - `GM_setValue`/`GM_getValue`/`GM_deleteValue`/`GM_listValues` are persisted,
    scoped per script, in `userscripts/gm_storage.json` (writes are coalesced
    on a short debounce and written atomically; the configuration file is
    deliberately not used, since these are written far too often to
    re-serialize it each time). Because `GM_getValue` is synchronous in the GM
    API, values are preloaded into each script's descriptor at injection time
    and read from that snapshot in-page, so an ordinary `GM_getValue` costs no
    request. Uninstalling a script drops its values.
  - `GM_xmlhttpRequest` is relayed server-side, so it has no CORS restrictions
    — the one capability a real content script cannot have. Three independent
    controls gate it: the origin-bound token, the requesting script's own
    `@connect` declarations (as Tampermonkey requires, so compatibility is
    unaffected), and a filter rejecting loopback, RFC1918, carrier-grade NAT,
    link-local (including the cloud metadata address) and IPv4-mapped
    equivalents. Redirects are followed manually so `@connect` and address
    filtering re-run on every hop rather than letting an allow-listed host
    bounce the request to `127.0.0.1`. Methods are restricted, `Host` and
    hop-by-hop request headers cannot be set, and responses are size-capped.
  - `@resource` payloads may be binary. They are stored as bytes with the
    content type they were served as; text small enough to matter is inlined
    into the script's descriptor so `GM_getResourceText` stays synchronous,
    while anything binary or oversized is reachable through
    `GM_getResourceURL`, served from the reserved path with its original bytes,
    content type and `X-Content-Type-Options: nosniff`. `GM_getResourceText` on
    a binary resource returns `null` and logs a note pointing at
    `GM_getResourceURL` rather than returning mojibake.
  - `GM_addValueChangeListener`/`GM_removeValueChangeListener` are implemented.
    Changes fire locally, reach other same-origin tabs over `BroadcastChannel`
    (free, no request), and reach other origins and other devices behind the
    same proxy by polling a read endpoint — which only runs while at least one
    listener is registered, so a page with no listeners issues no extra
    requests. The read endpoint requires the requesting URL to satisfy the
    script's own `@match`/`@include`, so it can never reveal more than the
    page's own descriptor already contained.
  - `GM_registerMenuCommand` now has a real surface: a small floating menu,
    injected only once a script actually registers a command, hosted in a closed
    shadow root so neither the page's CSS nor Privaxy's can reach across.
    Commands are still reachable from the console via
    `__privaxyUserscriptMenu()`.
  - Userscripts can be disabled for a single tab from that menu, backed by
    `sessionStorage` — per-tab by construction, so the proxy needs no notion of
    a tab. Other tabs are unaffected; `__privaxyUserscriptsEnableTab()` restores
    them, since disabling removes the menu that turned them off.
  - Userscripts installed from a URL are re-fetched on the same 24h timer as the
    filter lists and recompiled in place, so upstream changes are picked up
    without a restart. The refresh re-reads the configuration from disk rather
    than reusing the updater's own copy: userscript changes deliberately bypass
    that channel, so its copy is stale with respect to them and recompiling from
    it would drop every script installed since startup.
  - `@updateURL` and `@downloadURL` are honored, both defaulting to the URL the
    script was installed from. When they differ, only the (small) `@updateURL`
    document is fetched to compare `@version`, and the body is downloaded solely
    when that version is newer — versions are ordered as dotted numbers, so
    `1.2.10` correctly supersedes `1.2.9`, falling back to plain inequality for
    schemes that cannot be ordered. Scripts that split metadata and body, a
    common Greasyfork layout, previously re-downloaded the whole body on every
    cycle.
  - A **Check for updates** button on the Userscripts page refreshes on demand
    instead of waiting out the timer, reporting per script whether it was
    updated, already current, or failed and why. Unlike the periodic refresh it
    holds the save lock, so a changed `@name` or `@version` is persisted.
  - New `userscripts.allow_private_network_requests` setting (default off, with
    a toggle on the Userscripts page) permits the relay to reach private
    addresses. It is off by default because the relay runs server-side: the
    proxy usually sits *inside* a LAN and can reach routers, admin panels and
    metadata endpoints no page could contact. Changes apply immediately, with
    no reload.
  - Changes apply to the next page load with no reload or restart: compiled
    scripts live in a shared store that each API mutation replaces in place,
    and the store is also refreshed on `SIGHUP` so a hand-edited
    `[userscripts]` section takes effect. Each script is emitted in its own
    `nonce`d script element, so a syntax error in one script cannot abandon the
    others or the ad-blocking payload, and the CSP nonce is kept in a closure
    rather than published on `window`.
  - Note that a userscript installed here runs on **every client behind the
    proxy**, in the page's main world (a proxy has no isolated world to offer),
    which is a wider blast radius than a browser extension installed in one
    profile. The Userscripts page says so where scripts are added.
  - **Not supported.** A userscript engine built into a proxy cannot reach full
    Tampermonkey parity, and some of what is missing is structural rather than
    unfinished. Known gaps, so a script that misbehaves can be diagnosed instead
    of guessed at:
    - *No isolated world, and there cannot be one.* Scripts run in the page's
      main world, so `unsafeWindow === window`, page scripts can read and clobber
      anything a userscript leaves reachable, and anti-adblock can detect the
      injection. Each script is still wrapped in its own function, so its `var`,
      `let`, `const`, `function` and `class` declarations do not leak to the page
      — only an undeclared assignment or an explicit `window.x = …` does.
    - *Pages the proxy never sees get nothing.* A site with an active service
      worker serving navigations from cache, `file://`, `chrome://`, browser-cache
      hits and any traffic not routed through Privaxy are all invisible to it, so
      no script runs there. A browser extension sees all of them.
    - *`@grant` is parsed and displayed but not enforced.* Every script receives
      every implemented API regardless of what it declared, including
      `@grant none`. This is deliberately forgiving — a script that forgot to
      declare a grant still works — but it is a deviation.
    - *Not implemented:* `GM_cookie` (the proxy has no cookie jar for the
      browser's cookies; it only sees `Cookie` headers in flight),
      `GM_getTab`/`GM_saveTab`/`GM_getTabs` (no tab identity exists on the proxy
      side), `GM_download` (it would mean the proxy writing files to its own disk
      on a page's behalf), `GM_addElement`, the batch `GM_setValues`/`GM_getValues`
      forms, and `window.onurlchange`.
    - *`GM_notification` writes to the console* rather than raising a real
      notification, and `GM_setClipboard` needs a user gesture like any page-context
      clipboard write.
    - *Metadata ignored:* `@sandbox`, `@unwrap`, `@top-level-await`, `@icon`,
      `@supportURL`, `@antifeature`. Unknown directives are skipped, not rejected.
    - *`@resource` payloads are byte-exact but not inlined as text when binary or
      over 256 KB* — `GM_getResourceText` returns `null` for those and the data is
      reachable only through `GM_getResourceURL`.
    - *`GM_xmlhttpRequest` is not a transparent `XMLHttpRequest`.* Responses are
      decoded as lossy UTF-8, so binary bodies are unusable; `abort()` only
      suppresses the callbacks, since the server-side request is already in
      flight; there is no `onprogress`/`onreadystatechange`; redirects are capped
      at 5 hops, timeouts at 60s (default 30s) and responses at 8 MB; and the
      request only reaches hosts the script declared with `@connect`.
    - *Value-change notification is not instant across origins.* Same-origin tabs
      are updated immediately over `BroadcastChannel`; a change made on a
      different origin or another device is picked up by a 15s poll, and only
      while a listener is registered.
    - *Per-tab disable is per-tab **per origin*** — it is `sessionStorage`, so
      disabling on one site does not disable on another in the same tab.
    - *Storage limits:* 1000 keys per script and 64 KB per value; a script body
      or fetched `@require`/`@resource` is capped at 2 MB. Writes are flushed on a
      500 ms debounce, so values set immediately before a crash can be lost.
    - *No script ordering or import/export in the UI.* Injection order is
      configuration order, changeable only by editing the file.
- Proxy performance overhaul:
  - *HTML responses now stream.* The proxy previously withheld an HTML
    response — status line, headers and all — until the entire upstream
    document had been downloaded and fed through the rewriter, so the browser
    could not start parsing (or prefetching subresources) until the last
    upstream byte arrived. The rewritten document now streams to the client as
    it is produced, and the rewriter pipeline is bounded end-to-end, so a slow
    client backpressures the upstream download instead of the whole document
    buffering in memory.
  - *WebSocket tunnels no longer squeeze through a 32-byte buffer.* The duplex
    buffer bridging the client and upstream halves of an upgraded connection
    was 32 bytes, forcing a task wakeup roughly every 32 bytes transferred;
    it is now 64 KiB.
  - *The adblock engine is shared, not funneled through one thread.* The
    `single-thread` adblock feature is dropped; the engine (Send + Sync) is
    now called directly from request tasks, removing a channel round-trip and
    two cross-thread handoffs from every request. Matching itself still
    serializes briefly on the engine's internal regex-manager lock — the same
    one-core ceiling as the old blocker thread, far above proxy request rates
    — but the per-request overhead around it is gone. Filter-list updates
    build the replacement engine on the blocking pool and swap it in
    atomically, so requests keep matching against the old engine during a
    multi-second list rebuild instead of stalling behind it.
  - *One cosmetic lookup per page instead of two.* The URL-scoped cosmetic
    lookup (`url_cosmetic_resources`) ran once for the `<head>` injection and
    again at end-of-body; the end-of-body pass now reuses the first lookup and
    only resolves the generic class/id-indexed selectors on top.
  - Dashboard events are only constructed when a client is actually watching
    the live requests feed; statistics counters are atomics instead of
    mutexes; the HTML rewriter no longer compiles a (redundant) regex per
    response and scans each element once instead of twice.
  - New 5-minute read timeout on proxied requests bounds a peer that stops
    sending mid-response without closing (previously such a request hung
    forever); generous enough not to disturb long-polls or quiet SSE streams.
- A configuration file that fails to parse no longer takes the server down.
  `read_configuration` unwrapped the parse error, so a hand-edited file with (for
  example) a duplicate TOML key panicked a worker on `SIGHUP` and killed both the
  proxy and web-UI loops while the process kept running — both ports stopped
  listening with no way back except a restart. The last configuration that parsed
  is now kept and reused, so a reload over a broken file logs the error and
  carries on serving with the previous settings, then picks up the corrected file
  on the next reload. The CA reload in the same path no longer unwraps either.
- The PAC route now also answers at `/wpad.dat`, so DNS-based WPAD
  auto-discovery (`http://wpad.<search domain>/wpad.dat`) can point straight
  at Privaxy without needing a rewrite in a fronting reverse proxy.
- New `network.gui_url` setting: full base URL of the web GUI as reachable by
  clients, e.g. `gui_url = "http://proxy.example.lan"` when the GUI sits
  behind a reverse proxy. Used verbatim for links back to the GUI on proxy
  error pages (the "exclude this host" button), winning over `listen_url` and
  the bound/dialed address. Fixes the exclude link pointing at an unreachable
  container IP when Privaxy runs behind Docker NAT with the GUI fronted by a
  reverse proxy on a different port. Editable from Settings → General
  (network section) as "GUI URL"; must start with `http://` or `https://`
  (validated in both the form and the API), and clearing the field unsets it.
  Older API clients that omit the field keep the stored value.
- Fix PAC rendering of CIDR bypass rules entered as `subnet/22`: the GUI
  stores the bare prefix length, which was emitted verbatim into
  `isInNet(host, subnet, "22")` — an invalid mask for standard PAC engines,
  so those DIRECT rules silently never matched. Prefix lengths are now
  converted to dotted-decimal masks at render time (already-dotted masks are
  passed through), fixing existing configs without rewriting them.
- Failing filter lists are now surfaced in the web UI
  - Filter lists that fail to download or stop serving valid rules (moved
    URL, HTML error page, empty list) used to fail silently in the background
    updater. Settings → Filters now shows a warning panel listing each
    failing list with its error, last attempt time and consecutive failure
    count, and offers per-entry **Edit** (fix the URL, title or category in a
    prefilled modal) and **Remove** actions. The panel is hidden while every
    list is healthy. Failures are tracked in memory (keyed by the filter's
    file name) and reconciled on configuration changes, so disabling or
    removing a list clears its entry.
  - Editing validates the new URL the same way adding a filter does (must
    serve a `text/plain` list with parseable rules) and keeps the entry's
    enabled state; a URL already used by another filter is rejected with a
    `409`.
  - A periodic refresh no longer aborts the remaining lists when one list
    fails to download: each list is now updated independently and failures
    are recorded per list.
  - New authenticated API routes: `GET /api/filters/failures` and
    `PATCH /api/filters`. `/api/filters` routes now match the exact path
    only, so stray sub-paths 404 instead of hitting the collection handlers.
- User-added filter lists can be edited and removed from the Filters page
  - Each user-added list row now has an edit (pencil) button opening a modal
    to rename the list, change its category or URL, or delete it. Built-in
    lists shipped with the package show no edit button and the API refuses to
    edit (`PATCH`) or remove (`DELETE`) them with a `403` — they can only be
    enabled/disabled. The failures panel follows the same rule: a failing
    built-in list offers a **Disable** action instead of Edit/Remove.
  - `GET /api/filters` responses now include each filter's `url` and an
    `is_default` flag, and `GET /api/filters/failures` entries carry
    `is_default` too.
- Dependency upgrade to latest versions (semver-aware; pre-releases such as
  `argon2 0.6.0-rc` and `tera 2.0.0-alpha` were intentionally not adopted).
  - Server HTTP/TLS stack: `hyper 0.14 → 1`, `http 0.2 → 1` (now via
    `hyper-util` + `http-body-util`), `rustls 0.21 → 0.23`,
    `tokio-rustls 0.24 → 0.26`, `hyper-rustls 0.24 → 0.27`,
    `reqwest 0.11 → 0.13`, `warp 0.3 → 0.4`. The whole TLS stack is pinned to
    the `ring` crypto provider so the MIPS/musl cross builds keep working
    (`aws-lc-rs` needs a C toolchain). A `ring` `CryptoProvider` is installed
    once at startup, as rustls 0.23 requires.
  - warp 0.4 dropped its built-in TLS and graceful-shutdown server, so the web
    GUI is now served through `hyper-util` with optional `tokio-rustls`
    termination; WebSocket live feeds continue to work via connection upgrades.
  - Frontend: `yew 0.19 → 0.23`, `yew-router 0.16 → 0.20`, `gloo-*` bumped,
    `web-sys`/`wasm-bindgen` refreshed, and the deprecated `reqwasm` replaced
    with `gloo-net`.
  - Other majors: `thiserror 1 → 2`, `toml 0.8 → 1`, `dirs 5 → 6`.
  - Behavior is unchanged; a set of characterization tests was added first to
    lock the proxy's CSP/request-type/upgrade logic, the TOML config
    round-trip, and CA-signed cert/server-config assembly.
- One-click exclusion of hosts that break under TLS interception
  - The proxy's 502 error page now names the failing host and offers an
    "Exclude this host" button. The button is a plain link to the web UI's new
    `/exclude?host=…` confirm page, so it rides the existing session auth:
    logged-in admins get a one-click confirm, everyone else lands on the login
    page first (the URL survives login). Values substituted into the error
    page are now HTML-escaped and the link's host is percent-encoded
    (previously the error reason was inserted unescaped).
  - The web UI address on the error page is derived from `network.listen_url`
    when set, otherwise from the bind address — falling back to the IP the
    client actually dialed when binding `0.0.0.0`.
  - New "Recent TLS interception failures" panel on Settings → Exclusions:
    clients that abort the interception handshake (typically certificate
    pinning — e.g. banking apps, RCS messaging) can never be shown an error
    page, so the proxy now records those hosts (deduplicated,
    most-recent-first, capped at 100, in memory) and the panel offers
    per-host **Exclude** and **Ignore** actions. Ignored hosts persist in the
    config (`ignored_tls_failures`) and survive restarts; existing config
    files without the field keep working.
  - New authenticated API routes: `GET /api/tls-failures` and
    `POST /api/tls-failures/ignore`.

## v0.7.1

- Fix WebSocket / protocol-upgrade connections hanging
  - Upgrade requests (`wss://`, and proprietary HTTP-upgrade transports like MMTLS long-link) could spin forever with `upgrade expected but not completed`. The proxy fabricated a `101 Switching Protocols` to the client regardless of what the upstream actually returned, so a failed upgrade left the client waiting on a tunnel that was never bridged. It now forwards the upstream's real response when it isn't a genuine `101`, and the dedicated upgrade HTTP client gained the same connection hardening (`connect_timeout`, `tcp_keepalive`, no idle pooling) as the main client.
  - Excluded hosts performing a plain-HTTP protocol upgrade are now blind-tunneled at the TCP level instead of being run through the (HTTP-only) upgrade bridge, so MITM-excluded apps using non-HTTP upgrade protocols work. Previously the exclusion list was only consulted on the `CONNECT` path, so excluding such a host had no effect on its plain-HTTP upgrade traffic.
  - When an opaque (non-WebSocket) upgrade is seen for a host that is *not* excluded, a warning is logged naming the host and suggesting it be added to the exclusions, instead of failing cryptically.
- Validate filter lists when added
  - Adding a filter now rejects URLs that do not serve a `text/plain` filter list (e.g. an HTML error/landing page returned with a `200`) with a `422`, instead of silently saving a broken filter. The error is surfaced in the web UI, and filters whose URL stops serving a list are dropped from the engine with a warning on the next refresh.
- Fix proxied requests randomly hanging/timing out
  - The outbound HTTP client had no connection timeouts, so a pooled keep-alive connection silently dropped by the remote would be reused and block until the OS TCP timeout (minutes). Added `connect_timeout`, `pool_idle_timeout`, and `tcp_keepalive`.
- DNS-over-HTTPS (DoH) interception
  - Detects DoH requests passing through the MITM proxy (RFC 8484 `application/dns-message`, JSON DoH, and known resolver endpoints)
  - `block` mode (default) refuses DoH so fallback-mode clients (e.g. default Firefox) revert to the system resolver, which Privaxy already sees — the HTTP-layer equivalent of the `use-application-dns.net` canary a non-DNS proxy cannot serve
  - `redirect` mode transparently forwards queries to a configured `upstream` resolver
  - Configured under `[network.doh]` (`mode`, `upstream`, `extra_hosts`) or from the web UI under Settings → General; MITM-excluded hosts are left untouched
- Fix cookie not invalidating upon logout/cred change
- All four engine-matching call sites now use match_url (canonical, default port stripped); the outbound request and stats still use the raw uri with its port, so nothing about proxying changes. This was silently breaking every hostname-anchored (||host/path) network rule on every HTTPS site
- Update ublock annoyances url
- Add support for MIPS, MIPSLE
- Injected uBlock scriptlets now actually run
  - Even after the 0.7.0 scriptlet repair, every injected `##+js(...)` scriptlet was a silent no-op. adblock-rust emits scriptlet bodies that reference an ambient `scriptletGlobals` object (uBlock Origin supplies it in its own injector; adblock-rust leaves it to the embedder), so the first internal call threw `ReferenceError: scriptletGlobals is not defined`, which each scriptlet's own `try/catch` swallowed. Privaxy now defines `scriptletGlobals` at the top of the injected payload, so `abort-current-script`, `prevent-addEventListener`, `abort-on-property-read`, `set-cookie`, etc. take effect.
- Procedural cosmetic filtering
  - Non-CSS procedural filters are no longer dropped (previously only filters reducible to plain CSS were applied). `:has-text`, `:matches-css`/`-before`/`-after`, `:matches-attr`, `:matches-path`, `:min-text-length`, `:upward`, `:xpath`, and the `:remove()`/`:style()`/`remove-attr`/`remove-class` actions are now evaluated in-page by an injected shim.
  - The shim re-runs on DOM mutations and recurses into same-origin child frames (`about:blank`/`srcdoc`/`data:` with `allow-same-origin`), so ad content written into such frames after load is also matched. Cross-origin frames and closed shadow DOM remain out of reach.
- Scriptlet error logging (debugging)
  - New opt-in `debug.scriptlet_console_logging` (off by default), toggleable from Settings → Debug, surfaces errors thrown by injected scriptlets in the page console as `[privaxy scriptlet]` entries instead of swallowing them.
- Live log streaming in the web UI
  - Settings → Debug now shows the server's log output in real time
  - The level can be changed in the webui
- Fix cosmetic "modified responses" statistic undercount
  - Pages where only element-hiding (`display: none`) selectors were injected were not counted as modified; any injected cosmetic CSS now counts

## v0.7.0

- Built-in authentication for the web UI and API
  - First-run setup page for choosing an admin username + password
  - 30-day HMAC-signed session cookie
  - `X-Api-Key` header for programmatic access; rotate from the Account settings page
  - Recovery: delete `auth.password_hash` from the config and restart to re-trigger setup
- PAC file generation
- Updated uBlock assets
- Scriptlet (`##+js(...)`) support repaired
  - uBlock Origin's modern `scriptlets.js` (the `builtinScriptlets.push({...})` format) is now compiled at build time into the JSON `Resource` schema adblock-rust consumes, with each scriptlet's transitive dependencies inlined. The legacy `///`-header parser was silently producing zero scriptlets against the current upstream format.
  - Scriptlets are now injected at the top of `<head>` instead of appended at end-of-body, so they execute before page scripts.
- Bump `adblock` crate from 0.8.9 to 0.12.5
  - Procedural cosmetic filters that reduce to pure CSS are still applied as styles; non-CSS procedural filters (those that need in-page JS) are dropped
- Refresh filters once a day
- Fix(?) memory leak
- Inject into CSP-protected websites
- Add docker compose example


## v0.6.0

- Remove gui app
- Bring back web gui
- API improvements
- Support for custom filters
- Filterlists.com integration
- SSL support on the web gui
  - Optional to specify. If not provided and `tls` is set
    to `true`, a SSL certificate is created with the proxy
    CA cert
- Allow users to specify their own CA cert
- Improve frontend routing
- Update dependencies
- Allow customization of bind address
- Static files and API are now under the same route
  - Static files are found as before
  - API calls are under `/api`
- Privaxy now honors SIGHUP
  - `systemctl reload privaxy` will reload privaxys configuration
- Change settings in webserver
  - Upon a successful change, the server will reload


## v0.5.2

- Wildcards are allowed in configurable exclusions.

## v0.5.1

- Apple build of desktop app is now notarized.

## v0.5.0

- Add builds for apple silicon

## v0.4.0

- Now ships as a desktop gui app.
- A new "nogui" binary is shipped alongside the gui version.
- Fixes an issue where cosmetic filtering may not have worked anymore when faulty rules existed in filter lists.

## v0.3.1 (December 4, 2022)

- Update ublock resources.
- Bump dependencies.

## v0.3.0 (June 21, 2022)

- Make use of system resolver.
- Fix windows build (<https://github.com/Barre/privaxy/issues/23>).

## v0.2.0 (June 20, 2022)

- Inject styles and scripts before the `</body>` and `</html>` tags.
- Windows build

## v0.1.0 (May 10, 2022)

- Initial release
