# Changelog

## 0.7.1

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
