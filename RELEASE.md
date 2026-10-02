# Privaxy v0.8.0

Privaxy v0.8.0 adds userscripts, filtering for selected hosts, and broader HTTP
CONNECT support. It also improves streaming performance, filter-list recovery,
and the tools for diagnosing sites that break under interception.

## Highlights

- **Userscripts managed from the web UI.** Install by URL or paste, edit source,
  enable or disable individual scripts, and check for updates. Supports common
  Greasemonkey/Tampermonkey metadata and APIs, persistent storage, resources,
  menu commands, and server-side requests controlled by each script's
  `@connect` rules. URL-installed scripts also check for updates automatically.
- **Filter only selected hosts.** Inclusion mode intercepts the hosts you
  select and tunnels everything else. Exclusions always take precedence, and
  an empty inclusion list bypasses all hosts. The same policy applies to
  HTTP, HTTPS, and PAC files; existing configurations keep their previous mode.
- **HTTP CONNECT and incoming proxy chaining.** Compatible HTTP proxies and
  adapters can send both plain HTTP and HTTPS through CONNECT to Privaxy,
  including on nonstandard ports. Traffic uses the existing filtering,
  injection, and inclusion/exclusion policies. The README includes tun2proxy
  as one example, with routing configured by the user.
- **Better filter-list management.** Refresh all enabled lists on demand, see
  download failures and their causes, and edit or remove user-added lists.
  Empty or invalid caches are recovered or downloaded again, and atomic
  replacement prevents failed writes from truncating a working list.
- **Easier interception troubleshooting.** Proxy error pages link to an
  exclusion confirmation page. The UI also lists recent TLS interception
  failures, with actions to exclude or ignore a host. A configurable GUI URL
  keeps these links usable behind reverse proxies and Docker NAT.

## Reliability and performance

- HTML responses stream as they are rewritten, allowing browsers to start
  rendering before the complete document arrives. Bounded buffering limits
  memory use when downstream clients are slow.
- Larger WebSocket buffers, a shared adblock engine, and fewer repeated
  cosmetic lookups reduce overhead. Filter updates replace the engine without
  pausing requests for the full rebuild.
- The proxy waits for initial filter loading before accepting traffic. The
  web UI remains available during loading and reports list failures.
- Invalid configuration edits retain the last working configuration. Reloads
  no longer race for the web UI listener, and bind failures retry.
- Fixes cover filtering on upgraded requests, WebSocket/MMTLS handling,
  truncated upstream responses, replacement-resource decoding, IPv6
  certificates, and CSP compatibility for injected content.
- PAC files are also served at `/wpad.dat`, and CIDR bypass rules now render
  valid subnet masks.
- The HTTP/TLS stack and frontend dependencies have been updated. Docker
  examples include log rotation to limit disk usage.

## Upgrading and compatibility

- Existing configuration files remain supported. For v0.7.1 configurations,
  inclusion mode defaults off and no userscripts are installed automatically.
- If upgrading from a development build with userscripts, **reload open pages**
  after upgrading. Userscript endpoints now use tokens bound to each script
  and matched page; disabling a script or changing its match rules revokes
  access.
- Installed userscripts run on matching pages for every client behind the
  proxy, in the page's main JavaScript world. This is a subset of browser
  userscript-manager functionality; see the changelog for supported APIs and
  known limitations. Requests to private networks remain disabled by default.
- For incoming proxy chains, preserve destination hostnames in CONNECT so
  domain filtering and HTTPS certificates work correctly. Clients still need
  to trust Privaxy's CA. This release does not add configuration for routing
  Privaxy's outbound traffic through another upstream proxy. TUN setup,
  routing, and UDP/QUIC handling remain the user's responsibility.
- To pin this release in Docker, use `ghcr.io/joshrmcdaniel/privaxy:0.8.0`.
  Existing containers need to be recreated to adopt the log-rotation options
  shown in the README.

See the [full changelog](https://github.com/joshrmcdaniel/privaxy/blob/v0.8.0/CHANGELOG.md)
and [proxy-chaining setup](https://github.com/joshrmcdaniel/privaxy/blob/v0.8.0/README.md#6-http-connect-and-proxy-chaining)
for details.
