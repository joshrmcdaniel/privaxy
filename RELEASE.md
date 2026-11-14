# v0.8.1

Privaxy v0.8.1 improves uBlock Origin filter-list compatibility, adds optional
persistent statistics, and fixes HTTP/2 failures and page-loading delays.

## Highlights

- **Updated uBlock Origin filtering.** Use the combined official CDN lists for
  Ads, Badware risks, Privacy, Quick fixes, and Unbreak. Bundled scriptlets are
  updated to uBO 1.76.2, including newer JSON-edit and video-response hooks,
  shared helpers, and trusted-scriptlet permissions.
- **Conditional rules and sub-lists.** Evaluate nested filter-list conditions
  and download active relative `!#include` files. This fixes updates for EasyList
  Cookie and Fanboy's Annoyance and loads their uBO-specific rules. Failed
  sub-list downloads preserve the previous complete cache. Logs now show how
  many rules loaded and why individual rules were rejected.
- **Persistent statistics on the Dashboard.** Optional history provides time
  ranges, trends, top domains and clients, and paginated requests. Settings
  control privacy, retention, storage limits, exclusions, and clearing history.
  With persistence off or Anonymous mode selected, the Dashboard retains its
  original live layout. Old `/history` bookmarks redirect to the Dashboard.
  Request history shows paths separately from domains, truncating long values
  with the full path available on hover. Paths are stored without the first `/`,
  which is restored in the UI. Domains, endpoints, and clients are stored once
  and shared across request records to reduce repeated data. Assign friendly
  client names or exclude client IPs from statistics and the live Requests log
  in Statistics settings; excluded clients still receive normal filtering.
- **More reliable live views and settings.** Dashboard statistics, Requests,
  and logs show connection status and reconnect automatically. Settings retain
  unsaved edits after errors, report save results accurately, and fit smaller
  screens more comfortably.
- **Version and update status.** The footer links the running Privaxy version
  to the project and automatically shows an update link when a newer stable
  release is detected.

## Reliability and performance

- Larger HTTP/2 header limits fix 502 protocol errors on responses with large
  CSP or Set-Cookie headers. Intercepted TLS connections advertise HTTP/2 so
  browsers can multiplex requests; adaptive flow control and TCP_NODELAY reduce
  delays. Known-empty requests can recover from retryable HTTP/2 failures.
- IP-address CONNECT requests use TLS ClientHello SNI for certificates,
  hostname policy, and upstream TLS verification while retaining the original
  destination IP. Protocol detection and TLS handshakes have bounded timeouts.
  CONNECT traffic to port 853 tunnels DNS-over-TLS without interception.
- Proxy error pages and logs include underlying DNS, TLS, socket, and HTTP/2
  failure causes. HTML modification counts no longer double-count a response
  that receives both scripts and cosmetic styles.
- CI validates release tags against the package version, avoids stale package
  assets, improves build caches, and keeps pull-request Docker checks separate
  from image publishing.

## Upgrading and compatibility

- Existing configurations remain supported. Persistent statistics stay off
  until enabled in Settings. Endpoints follow domain privacy settings; query
  strings, URL credentials, headers, and bodies are never saved in statistics.
  Existing history migrates to statistics storage version 3 when opened;
  earlier builds that only support versions 1 or 2 cannot read the upgraded
  database. Client names stay in configuration when saved history is cleared.
- Legacy subscriptions for the five updated uBO lists migrate automatically
  while preserving enabled states. An existing CDN subscription takes
  precedence over its old source-list duplicate. Refresh enabled lists and
  reload open pages after upgrading to use the latest rules and scriptlets.
- Filter syntax and browser integration still differ from the uBO extension.
  Unsupported-rule warnings describe individual skipped rules, not failed
  subscription downloads, and this update does not guarantee identical video
  ad blocking on every site.
- To pin this release in Docker, use `ghcr.io/joshrmcdaniel/privaxy:0.8.1`.

See the [full changelog](https://github.com/joshrmcdaniel/privaxy/blob/v0.8.1/CHANGELOG.md)
and [setup documentation](https://github.com/joshrmcdaniel/privaxy/blob/v0.8.1/README.md#setup)
for details.
