// Privaxy userscript runtime.
//
// Injected into the document head ahead of the userscripts themselves.
// `PRIVAXY_NONCE` is supplied by the enclosing IIFE and deliberately stays in
// this closure: exposing the CSP nonce on `window` would let page scripts
// bypass the page's own Content-Security-Policy.
//
// Avoid writing the literal sequence `<` + `script` anywhere in this file: it
// is served inside an inline script element, and HTML5's double-escaped
// script-data states can change where the browser thinks that element ends.
//
// Userscripts run in the page's main world — a proxy has no isolated world to
// offer — so `unsafeWindow` is simply `window`.

// The element this runtime is executing in, captured before anything can move
// it. Its text is blanked once startup finishes so later page scripts cannot
// read PRIVAXY_ENDPOINT_TOKEN out of the DOM.
var privaxyRuntimeElement = document.currentScript;

// GM storage. Values arrive preloaded in each script's descriptor, because
// GM_getValue is synchronous in the GM API and cannot wait on a request. Reads
// therefore hit this in-memory snapshot; writes update it and are persisted
// asynchronously through the reserved same-origin endpoint.
var privaxyValueStores = Object.create(null);
var privaxyMenuCommands = [];

// Listeners registered via GM_addValueChangeListener, keyed by script id.
var privaxyValueListeners = Object.create(null);
var privaxyListenerCount = 0;
var privaxyPollTimer = null;

// Same-origin cross-tab notification, which costs nothing and covers the common
// case of two tabs on one site. Cross-origin and cross-device changes arrive via
// the poll below instead.
var privaxyValueChannel = null;
try {
    privaxyValueChannel = new BroadcastChannel('privaxy-userscript-values');
} catch (error) {
    // Not available in this context; local and polled notification still work.
}

// Per-tab disable. sessionStorage is scoped to one tab by construction, so this
// needs no notion of a tab on the proxy side. Scoped per origin, which is the
// same granularity userscripts themselves run at.
var PRIVAXY_TAB_DISABLED_KEY = '__privaxy_userscripts_disabled__';

function privaxyTabDisabled() {
    try {
        return window.sessionStorage.getItem(PRIVAXY_TAB_DISABLED_KEY) === '1';
    } catch (error) {
        // Storage can be blocked outright; treat that as "not disabled".
        return false;
    }
}

function privaxySetTabDisabled(disabled) {
    try {
        if (disabled) {
            window.sessionStorage.setItem(PRIVAXY_TAB_DISABLED_KEY, '1');
        } else {
            window.sessionStorage.removeItem(PRIVAXY_TAB_DISABLED_KEY);
        }
    } catch (error) {
        console.error('[privaxy userscript] unable to record the per-tab setting', error);
    }
}

function privaxyValueStore(scriptId, preloaded) {
    if (!privaxyValueStores[scriptId]) {
        var store = Object.create(null);
        if (preloaded) {
            Object.keys(preloaded).forEach(function (key) {
                store[key] = preloaded[key];
            });
        }
        privaxyValueStores[scriptId] = store;
    }

    return privaxyValueStores[scriptId];
}

// Pending writes are batched per tick: a script that calls GM_setValue in a
// scroll handler produces one request per frame rather than one per call.
var privaxyPendingWrites = Object.create(null);
var privaxyFlushScheduled = false;

/// Deliver a change to this page's listeners for `scriptId`.
function privaxyNotifyListeners(scriptId, key, oldValue, newValue, remote) {
    var listeners = privaxyValueListeners[scriptId];
    if (!listeners) {
        return;
    }

    Object.keys(listeners).forEach(function (id) {
        try {
            listeners[id](key, oldValue, newValue, remote);
        } catch (error) {
            console.error('[privaxy userscript] a value change listener threw', error);
        }
    });
}

if (privaxyValueChannel) {
    privaxyValueChannel.onmessage = function (event) {
        var change = event && event.data;
        if (!change || !change.script) {
            return;
        }

        // Keep this tab's snapshot in step with the writing tab before firing,
        // so a listener reading GM_getValue sees the new value.
        var store = privaxyValueStores[change.script];
        if (store) {
            if (change.newValue === null || change.newValue === undefined) {
                delete store[change.key];
            } else {
                store[change.key] = change.newValue;
            }
        }

        privaxyNotifyListeners(change.script, change.key, change.oldValue, change.newValue, true);
    };
}

function privaxySchedulePersist(scriptId, key, value) {
    if (!PRIVAXY_ENDPOINT_TOKEN) {
        // No token means no derivable page origin; values stay in memory for
        // the life of the page.
        return;
    }

    if (!privaxyPendingWrites[scriptId]) {
        privaxyPendingWrites[scriptId] = Object.create(null);
    }
    // `null` is the deletion signal understood by the endpoint.
    privaxyPendingWrites[scriptId][key] = value === undefined ? null : value;

    if (privaxyFlushScheduled) {
        return;
    }
    privaxyFlushScheduled = true;

    Promise.resolve().then(function () {
        privaxyFlushScheduled = false;
        var pending = privaxyPendingWrites;
        privaxyPendingWrites = Object.create(null);

        Object.keys(pending).forEach(function (id) {
            fetch('/__privaxy__/gm/values', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                // Same-origin by construction: the proxy answers this path on
                // whatever origin the page is on.
                credentials: 'omit',
                body: JSON.stringify({
                    token: PRIVAXY_ENDPOINT_TOKEN,
                    script: id,
                    values: pending[id]
                })
            })
                .then(function (response) {
                    if (!response.ok) {
                        console.error(
                            '[privaxy userscript] failed to persist values (HTTP ' +
                                response.status + ')'
                        );
                    }
                })
                .catch(function (error) {
                    console.error('[privaxy userscript] failed to persist values', error);
                });
        });
    });
}

function privaxyBroadcastChange(scriptId, key, oldValue, newValue) {
    if (!privaxyValueChannel) {
        return;
    }

    try {
        privaxyValueChannel.postMessage({
            script: scriptId,
            key: key,
            oldValue: oldValue === undefined ? null : oldValue,
            newValue: newValue === undefined ? null : newValue
        });
    } catch (error) {
        // A value that cannot be structured-cloned still reached this tab's
        // listeners and the server; only cross-tab delivery is lost.
        console.warn('[privaxy userscript] value change not broadcast to other tabs', error);
    }
}

// Interval between polls once at least one listener exists. Long enough to be
// negligible, short enough that a cross-device change lands while the page is
// still open.
var PRIVAXY_POLL_INTERVAL_MS = 15000;

/// Poll the reserved endpoint for values changed elsewhere (another origin, or
/// another device behind the same proxy). BroadcastChannel already covers
/// same-origin tabs, so this is the fallback rather than the primary path.
function privaxyStartPolling() {
    if (privaxyPollTimer !== null || !PRIVAXY_ENDPOINT_TOKEN) {
        return;
    }

    privaxyPollTimer = setInterval(function () {
        Object.keys(privaxyValueListeners).forEach(function (scriptId) {
            var listeners = privaxyValueListeners[scriptId];
            if (!listeners || Object.keys(listeners).length === 0) {
                return;
            }

            fetch('/__privaxy__/gm/read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'omit',
                body: JSON.stringify({ token: PRIVAXY_ENDPOINT_TOKEN, script: scriptId })
            })
                .then(function (response) {
                    return response.ok ? response.json() : null;
                })
                .then(function (payload) {
                    if (!payload || !payload.values) {
                        return;
                    }
                    privaxyReconcile(scriptId, payload.values);
                })
                .catch(function () {
                    // A failed poll is not worth reporting on every tick.
                });
        });
    }, PRIVAXY_POLL_INTERVAL_MS);
}

/// Apply a server snapshot over this page's store, firing listeners for keys
/// that actually differ.
function privaxyReconcile(scriptId, remoteValues) {
    var store = privaxyValueStores[scriptId];
    if (!store) {
        return;
    }

    var seen = Object.create(null);

    Object.keys(remoteValues).forEach(function (key) {
        seen[key] = true;
        var previous = store[key];
        var next = remoteValues[key];

        // Compared by serialization: values are JSON round-tripped through the
        // server anyway, so this is the same notion of equality the store has.
        if (JSON.stringify(previous) !== JSON.stringify(next)) {
            store[key] = next;
            privaxyNotifyListeners(scriptId, key, previous, next, true);
        }
    });

    Object.keys(store).forEach(function (key) {
        if (!seen[key]) {
            var previous = store[key];
            delete store[key];
            privaxyNotifyListeners(scriptId, key, previous, undefined, true);
        }
    });
}

function privaxyLogPrefix(info) {
    return '[privaxy userscript: ' + info.name + ']';
}

function privaxyBuildApi(info) {
    var values = privaxyValueStore(info.id, info.values);

    function setValue(key, value) {
        var name = String(key);
        var previous = values[name];
        values[name] = value;
        privaxySchedulePersist(info.id, name, value);
        privaxyNotifyListeners(info.id, name, previous, value, false);
        privaxyBroadcastChange(info.id, name, previous, value);
    }

    function getValue(key, fallback) {
        var name = String(key);

        return Object.prototype.hasOwnProperty.call(values, name)
            ? values[name]
            : fallback;
    }

    function deleteValue(key) {
        var name = String(key);
        var previous = values[name];
        delete values[name];
        privaxySchedulePersist(info.id, name, null);
        privaxyNotifyListeners(info.id, name, previous, undefined, false);
        privaxyBroadcastChange(info.id, name, previous, null);
    }

    function addValueChangeListener(key, callback) {
        var name = String(key);
        if (!privaxyValueListeners[info.id]) {
            privaxyValueListeners[info.id] = Object.create(null);
        }

        var id = 'listener-' + privaxyListenerCount++;
        privaxyValueListeners[info.id][id] = function (changedKey, oldValue, newValue, remote) {
            if (changedKey === name) {
                callback(changedKey, oldValue, newValue, remote);
            }
        };

        // Polling only starts once something is actually listening, so a page
        // with no listeners makes no extra requests at all.
        privaxyStartPolling();

        return id;
    }

    function removeValueChangeListener(id) {
        var listeners = privaxyValueListeners[info.id];
        if (listeners) {
            delete listeners[id];
        }
    }

    function listValues() {
        return Object.keys(values);
    }

    function addStyle(css) {
        var style = document.createElement('style');

        // The proxy augments the page's CSP with a nonce rather than stripping
        // it, so an injected <style> needs that nonce to survive style-src.
        if (PRIVAXY_NONCE) {
            style.setAttribute('nonce', PRIVAXY_NONCE);
            style.nonce = PRIVAXY_NONCE;
        }

        style.textContent = css;
        (document.head || document.documentElement).appendChild(style);

        return style;
    }

    function log() {
        var args = [privaxyLogPrefix(info)].concat(Array.prototype.slice.call(arguments));
        console.log.apply(console, args);
    }

    function openInTab(url, options) {
        var background = options === true || (options && options.active === false);
        var opened = window.open(url, '_blank');

        if (opened && !background) {
            try {
                opened.focus();
            } catch (error) {
                // Popup blockers and cross-origin targets can refuse focus;
                // the tab is already open, so this is not worth failing over.
            }
        }

        return {
            close: function () {
                if (opened) {
                    opened.close();
                }
            }
        };
    }

    function setClipboard(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            // Requires a user gesture in most browsers; the rejection is
            // surfaced rather than swallowed so the script author can see why.
            return navigator.clipboard.writeText(String(text)).catch(function (error) {
                console.error(privaxyLogPrefix(info), 'GM_setClipboard failed', error);
            });
        }

        console.error(privaxyLogPrefix(info), 'GM_setClipboard is unavailable in this context');
    }

    function notification(details, ondone) {
        var text = details && typeof details === 'object' ? details.text : details;
        console.log(privaxyLogPrefix(info), 'notification:', text);

        if (typeof ondone === 'function') {
            ondone();
        }
    }

    function registerMenuCommand(caption, callback, accessKey) {
        // A proxy has no browser toolbar, so commands are surfaced in an
        // injected in-page menu (and remain reachable from the console via
        // __privaxyUserscriptMenu()).
        var id = privaxyMenuCommands.length;
        privaxyMenuCommands.push({
            id: id,
            script: info.name,
            caption: caption,
            accessKey: accessKey,
            run: callback
        });
        privaxyRefreshMenu();

        return id;
    }

    function unregisterMenuCommand(id) {
        privaxyMenuCommands = privaxyMenuCommands.filter(function (command) {
            return command.id !== id;
        });
        privaxyRefreshMenu();
    }

    // `@resource` payloads are fetched server-side. Text is delivered inline
    // with the descriptor so this stays synchronous; a binary or oversized
    // payload carries only a content type and is read through its URL. A name
    // that failed to load is absent and returns null rather than throwing, so
    // scripts can take their own fallback path.
    function resourceEntry(name) {
        var resources = info.resources || {};

        return Object.prototype.hasOwnProperty.call(resources, name)
            ? resources[name]
            : null;
    }

    function getResourceText(name) {
        var entry = resourceEntry(name);

        if (!entry) {
            return null;
        }
        if (entry.text === null || entry.text === undefined) {
            console.warn(
                privaxyLogPrefix(info),
                'GM_getResourceText("' + name + '") is unavailable: the resource is binary or too ' +
                    'large to inline. Use GM_getResourceURL instead.'
            );
            return null;
        }

        return entry.text;
    }

    // Served from the reserved path rather than encoded as a data: URI, so a
    // large image costs nothing until the page actually requests it.
    function getResourceUrl(name) {
        if (!resourceEntry(name) || !PRIVAXY_ENDPOINT_TOKEN) {
            return null;
        }

        return '/__privaxy__/gm/resource?script=' + encodeURIComponent(info.id) +
            '&name=' + encodeURIComponent(name) +
            '&token=' + encodeURIComponent(PRIVAXY_ENDPOINT_TOKEN);
    }

    // GM_xmlhttpRequest is relayed through the proxy, which performs the
    // request server-side: no CORS, no preflight, no opaque responses. The
    // proxy enforces the script's own @connect declarations and refuses private
    // addresses, so a rejection surfaces here as a non-2xx from the relay.
    function xmlHttpRequest(details) {
        if (!details || !details.url) {
            throw new Error('GM_xmlhttpRequest requires a url');
        }
        if (!PRIVAXY_ENDPOINT_TOKEN) {
            var unavailable = new Error(
                'GM_xmlhttpRequest is unavailable: no Privaxy endpoint token for this page'
            );
            if (typeof details.onerror === 'function') {
                details.onerror({ error: unavailable.message });
                return { abort: function () {} };
            }
            throw unavailable;
        }

        var aborted = false;

        fetch('/__privaxy__/gm/fetch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'omit',
            body: JSON.stringify({
                token: PRIVAXY_ENDPOINT_TOKEN,
                script: info.id,
                method: details.method || 'GET',
                // Resolved against the page so scripts may pass a relative URL,
                // as they can with a real XMLHttpRequest.
                url: new URL(details.url, location.href).href,
                headers: details.headers || {},
                body: details.data === undefined ? null : String(details.data),
                timeout: details.timeout
            })
        })
            .then(function (response) {
                return response.json().then(function (payload) {
                    return { ok: response.ok, status: response.status, payload: payload };
                });
            })
            .then(function (result) {
                if (aborted) {
                    return;
                }

                if (!result.ok) {
                    var message = (result.payload && result.payload.error) ||
                        ('relay failed with HTTP ' + result.status);
                    console.error(privaxyLogPrefix(info), 'GM_xmlhttpRequest:', message);
                    if (typeof details.onerror === 'function') {
                        details.onerror({ error: message, status: result.status });
                    }
                    return;
                }

                var payload = result.payload;
                // Shaped like the object Greasemonkey hands back, so existing
                // scripts read it without modification.
                var responseObject = {
                    readyState: 4,
                    status: payload.status,
                    statusText: payload.status_text,
                    responseText: payload.body,
                    response: payload.body,
                    finalUrl: payload.final_url,
                    responseHeaders: Object.keys(payload.headers || {})
                        .map(function (name) {
                            return name + ': ' + payload.headers[name];
                        })
                        .join('\r\n'),
                    context: details.context
                };

                if (payload.truncated) {
                    console.warn(
                        privaxyLogPrefix(info),
                        'GM_xmlhttpRequest response was truncated by the relay'
                    );
                }

                if (typeof details.onload === 'function') {
                    details.onload(responseObject);
                }
            })
            .catch(function (error) {
                if (aborted) {
                    return;
                }
                console.error(privaxyLogPrefix(info), 'GM_xmlhttpRequest failed', error);
                if (typeof details.onerror === 'function') {
                    details.onerror({ error: String(error) });
                }
            });

        // The server-side request cannot actually be cancelled; abort only
        // suppresses the callbacks, which is what scripts observe.
        return {
            abort: function () {
                aborted = true;
            }
        };
    }

    function promised(fn) {
        return function () {
            var args = arguments;

            return new Promise(function (resolve, reject) {
                try {
                    resolve(fn.apply(null, args));
                } catch (error) {
                    reject(error);
                }
            });
        };
    }

    return {
        GM_info: info.gmInfo,
        unsafeWindow: window,
        GM_addStyle: addStyle,
        GM_log: log,
        GM_setValue: setValue,
        GM_getValue: getValue,
        GM_deleteValue: deleteValue,
        GM_listValues: listValues,
        GM_openInTab: openInTab,
        GM_setClipboard: setClipboard,
        GM_notification: notification,
        GM_registerMenuCommand: registerMenuCommand,
        GM_unregisterMenuCommand: unregisterMenuCommand,
        GM_getResourceText: getResourceText,
        GM_getResourceURL: getResourceUrl,
        GM_addValueChangeListener: addValueChangeListener,
        GM_removeValueChangeListener: removeValueChangeListener,
        GM_xmlhttpRequest: xmlHttpRequest,
        // Tampermonkey exposes this capitalization too, and scripts use both.
        GM_xmlHttpRequest: xmlHttpRequest,
        // Modern scripts use the promise-based `GM.*` namespace.
        GM: {
            info: info.gmInfo,
            addStyle: promised(addStyle),
            setValue: promised(setValue),
            getValue: promised(getValue),
            deleteValue: promised(deleteValue),
            listValues: promised(listValues),
            openInTab: openInTab,
            setClipboard: promised(setClipboard),
            notification: promised(notification),
            registerMenuCommand: registerMenuCommand,
            unregisterMenuCommand: unregisterMenuCommand,
            getResourceText: promised(getResourceText),
            getResourceUrl: promised(getResourceUrl),
            addValueChangeListener: addValueChangeListener,
            removeValueChangeListener: removeValueChangeListener,
            xmlHttpRequest: xmlHttpRequest
        }
    };
}

// The injected menu lives in a shadow root so that neither the page's CSS nor
// ours can reach across. Created lazily: a page whose scripts register no
// commands gets no extra DOM at all.
var privaxyMenuHost = null;
var privaxyMenuRoot = null;

var PRIVAXY_MENU_STYLE =
    ':host{all:initial}' +
    '.wrap{position:fixed;bottom:16px;right:16px;z-index:2147483647;' +
    'font:13px/1.4 system-ui,-apple-system,Segoe UI,sans-serif}' +
    '.toggle{display:flex;align-items:center;justify-content:center;width:36px;height:36px;' +
    'border-radius:18px;border:none;background:#1f2937;color:#fff;cursor:pointer;' +
    'box-shadow:0 2px 8px rgba(0,0,0,.35);font-size:15px}' +
    '.toggle:hover{background:#374151}' +
    '.panel{display:none;margin-bottom:8px;min-width:220px;max-width:320px;' +
    'background:#fff;color:#111827;border-radius:8px;overflow:hidden;' +
    'box-shadow:0 6px 24px rgba(0,0,0,.3)}' +
    '.panel.open{display:block}' +
    '.head{padding:8px 12px;background:#f3f4f6;font-weight:600;font-size:12px;color:#374151}' +
    '.item{display:block;width:100%;box-sizing:border-box;padding:8px 12px;border:none;' +
    'background:none;text-align:left;cursor:pointer;font:inherit;color:inherit}' +
    '.item:hover{background:#eff6ff}' +
    '.script{display:block;font-size:11px;color:#6b7280}' +
    '.sep{height:1px;background:#e5e7eb}' +
    '.off{color:#b45309}';

function privaxyEnsureMenu() {
    if (privaxyMenuRoot) {
        return privaxyMenuRoot;
    }
    if (!document.body && !document.documentElement) {
        return null;
    }

    privaxyMenuHost = document.createElement('div');
    // A page could style an element by tag+position; an attribute this specific
    // is the least likely thing to collide.
    privaxyMenuHost.setAttribute('data-privaxy-userscript-menu', '');

    try {
        privaxyMenuRoot = privaxyMenuHost.attachShadow({ mode: 'closed' });
    } catch (error) {
        // Without shadow DOM the menu would inherit page styles unpredictably;
        // the console fallback still works, so skip the UI rather than inject
        // something that might disfigure the page.
        privaxyMenuHost = null;
        return null;
    }

    var style = document.createElement('style');
    style.textContent = PRIVAXY_MENU_STYLE;
    privaxyMenuRoot.appendChild(style);

    var wrap = document.createElement('div');
    wrap.className = 'wrap';

    var panel = document.createElement('div');
    panel.className = 'panel';

    var toggle = document.createElement('button');
    toggle.className = 'toggle';
    toggle.type = 'button';
    toggle.title = 'Privaxy userscripts';
    toggle.textContent = '\u2699';
    toggle.addEventListener('click', function () {
        panel.classList.toggle('open');
    });

    wrap.appendChild(panel);
    wrap.appendChild(toggle);
    privaxyMenuRoot.appendChild(wrap);
    privaxyMenuRoot.__panel = panel;

    (document.body || document.documentElement).appendChild(privaxyMenuHost);

    return privaxyMenuRoot;
}

function privaxyRefreshMenu() {
    // The menu is only worth showing once something is in it.
    if (privaxyMenuCommands.length === 0) {
        if (privaxyMenuHost && privaxyMenuHost.parentNode) {
            privaxyMenuHost.parentNode.removeChild(privaxyMenuHost);
            privaxyMenuHost = null;
            privaxyMenuRoot = null;
        }
        return;
    }

    var root = privaxyEnsureMenu();
    if (!root) {
        return;
    }

    var panel = root.__panel;
    panel.textContent = '';

    var head = document.createElement('div');
    head.className = 'head';
    head.textContent = 'Userscript commands';
    panel.appendChild(head);

    privaxyMenuCommands.forEach(function (command) {
        var item = document.createElement('button');
        item.className = 'item';
        item.type = 'button';
        // textContent, never innerHTML: a caption comes from a script and must
        // never be parsed as markup.
        item.textContent = command.caption;

        var script = document.createElement('span');
        script.className = 'script';
        script.textContent = command.script;
        item.appendChild(script);

        item.addEventListener('click', function () {
            try {
                command.run();
            } catch (error) {
                console.error('[privaxy userscript] menu command threw', error);
            }
        });
        panel.appendChild(item);
    });

    panel.appendChild(Object.assign(document.createElement('div'), { className: 'sep' }));

    var disable = document.createElement('button');
    disable.className = 'item off';
    disable.type = 'button';
    disable.textContent = 'Disable userscripts in this tab';
    disable.appendChild(
        Object.assign(document.createElement('span'), {
            className: 'script',
            textContent: 'Reloads the page. Other tabs are unaffected.'
        })
    );
    disable.addEventListener('click', function () {
        privaxySetTabDisabled(true);
        location.reload();
    });
    panel.appendChild(disable);
}

/// Invoke `run` at the point named by `runAt`.
function privaxyScheduleUserScript(runAt, run) {
    var readyState = document.readyState;

    if (runAt === 'document-start') {
        run();
        return;
    }

    if (runAt === 'document-body') {
        if (document.body) {
            run();
            return;
        }

        var observer = new MutationObserver(function () {
            if (document.body) {
                observer.disconnect();
                run();
            }
        });
        observer.observe(document.documentElement, { childList: true, subtree: true });
        return;
    }

    if (runAt === 'document-idle') {
        if (readyState === 'complete') {
            run();
        } else {
            window.addEventListener('load', run, { once: true });
        }
        return;
    }

    // document-end, the @run-at default.
    if (readyState === 'interactive' || readyState === 'complete') {
        run();
    } else {
        document.addEventListener('DOMContentLoaded', run, { once: true });
    }
}

/// Entry point emitted once per matched userscript.
///
/// `apiNames` is the parameter list of `factory`, authored on the Rust side, so
/// the two stay in step without duplicating the list here. A name this runtime
/// does not implement arrives as `undefined`, which lets scripts feature-detect
/// (`typeof GM_setValue !== 'undefined'`) instead of dying on a ReferenceError.
function privaxyRunUserScript(info, apiNames, factory) {
    // Checked per script rather than once, because the flag can only be set by
    // the menu, which reloads the page — so this is stable for the page's life.
    if (privaxyTabDisabled()) {
        return;
    }

    if (info.noFrames && window.top !== window.self) {
        return;
    }

    var api = privaxyBuildApi(info);
    var args = apiNames.map(function (name) {
        return api[name];
    });

    privaxyScheduleUserScript(info.runAt, function () {
        try {
            factory.apply(window, args);
        } catch (error) {
            // Userscripts are operator-authored, so a failure is always worth
            // reporting: a silently dead script is indistinguishable from one
            // that matched nothing.
            console.error(privaxyLogPrefix(info), error);
        }
    });
}

// Each userscript is emitted in its own script element so that a syntax error
// in one cannot abandon the others (or the ad-blocking payload). That isolation
// means the entry point has to be reachable across elements, hence the
// assignment to `window`. `PRIVAXY_NONCE` deliberately stays behind in this
// closure: publishing the CSP nonce would let page scripts bypass the page's
// own Content-Security-Policy.
window.__privaxyRunUserScript = privaxyRunUserScript;

// Startup is complete, so drop this element's source from the DOM. The runtime
// is already compiled and running; what remains in `textContent` is only of use
// to a page script wanting to read PRIVAXY_ENDPOINT_TOKEN. Being injected at the
// top of the document head, this executes before any of the page's own scripts
// get a chance to look.
if (privaxyRuntimeElement) {
    try {
        privaxyRuntimeElement.textContent = '';
    } catch (error) {
        // Not worth failing startup over.
    }
}

// Console access to @grant GM_registerMenuCommand entries, which have no
// toolbar to live in.
// Re-enabling has to be reachable from somewhere once the menu is gone, since
// disabling removes the very UI that turned it off.
window.__privaxyUserscriptsEnableTab = function () {
    privaxySetTabDisabled(false);
    location.reload();
};

window.__privaxyUserscriptMenu = function (id) {
    if (id === undefined) {
        return privaxyMenuCommands.map(function (command) {
            return { id: command.id, script: command.script, caption: command.caption };
        });
    }

    var command = privaxyMenuCommands.find(function (entry) {
        return entry.id === id;
    });

    return command ? command.run() : undefined;
};
