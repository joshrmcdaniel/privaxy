# Changelog

## Unreleased

- The PAC route now also answers at `/wpad.dat`, so DNS-based WPAD
  auto-discovery (`http://wpad.<search domain>/wpad.dat`) can point straight
  at Privaxy without needing a rewrite in a fronting reverse proxy.
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
