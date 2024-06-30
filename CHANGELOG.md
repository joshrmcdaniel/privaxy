# Changelog

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
