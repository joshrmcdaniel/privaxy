/*
 * Privaxy in-page procedural cosmetic filtering shim.
 *
 * The proxy can apply plain-CSS cosmetic rules server-side by injecting a
 * <style> block, but uBO/AdGuard procedural rules (:has-text, :matches-css,
 * :upward, :xpath, :remove(), …) need to be evaluated against the live DOM.
 * This shim receives those rules as JSON and applies them on load and on every
 * subsequent DOM mutation.
 *
 * It also adopts the plain-CSS cosmetic rules into every shadow root it finds.
 * That server-side <style> block is an *author-origin* stylesheet, so it stops at
 * every shadow boundary. uBO does not hit this because an extension injects
 * cosmetic CSS at **user** origin, and user-origin sheets do pierce shadow roots
 * — which is why the lists contain rules targeting shadow content that work
 * everywhere else. A proxy has no user-origin privilege, so `adoptedStyleSheets`
 * per root is the only equivalent. This is delivery *in addition to* the
 * document's own <style> block, not a replacement for it: the rules are read back
 * out of that very block rather than being sent a second time.
 *
 * The second argument is therefore not the CSS but a flag saying a block is
 * coming, so a page whose only cosmetic rules are plain CSS isn't mistaken for
 * one with nothing to do.
 *
 * Rules are evaluated against the top document AND every reachable child-frame
 * document. Same-origin frames built without a network fetch (`about:blank`,
 * `srcdoc`, `data:`) never reach the proxy, so the only way to filter their
 * contents is from the parent page — which we can do whenever the frame is
 * same-origin (e.g. a `sandbox` that includes `allow-same-origin`). Cross-origin
 * frames throw on document access and are silently skipped (those are filtered
 * via their own proxied response instead).
 *
 * Shadow roots are walked the same way, because `querySelectorAll` does not
 * pierce a shadow boundary: without an explicit walk, nothing in a root is ever
 * a candidate for any rule. Discovering roots requires hooking `attachShadow`
 * (see `installShadowHook`) plus a sweep for parser-built declarative roots.
 *
 * Each rule is a ProceduralOrActionFilter:
 *   { "selector": [ { "type": "css-selector", "arg": "…" }, … ],
 *     "action":   { "type": "style"|"remove"|"remove-attr"|"remove-class",
 *                   "arg": "…" } }      // action is optional => hide
 *
 * Defined as an idempotent global so repeated injection on a page is harmless.
 */
window.__privaxyApplyProcedural = window.__privaxyApplyProcedural || (function () {
    "use strict";

    var REGEX_LITERAL = /^\/(.*)\/([a-z]*)$/;

    // The nonce of the element we were injected in, needed only by the <style>
    // fallback in `deliverCss` — a page whose CSP allows inline styles by nonce
    // would otherwise block it. Read here because `document.currentScript` is
    // only meaningful while this script is executing, and kept in this closure:
    // publishing it would hand page scripts a way around the page's own CSP.
    // `adoptedStyleSheets`, the path this falls back from, is not inline content
    // and needs no nonce.
    var injectedNonce = "";
    try {
        injectedNonce = document.currentScript.nonce || "";
    } catch (err) {
        injectedNonce = "";
    }

    // Every shadow root we've been able to observe, open or closed.
    // `collectShadowRoots` partitions these per scope on each pass.
    var shadowRoots = new Set();

    // Roots we have seen attached to the document at least once. A root is only
    // eligible for eviction once it has been connected and then disconnected —
    // building a host offscreen, attaching its root and inserting it later is a
    // normal pattern, and evicting on the first "not connected" would drop it.
    var connectedRoots = new WeakSet();

    // Passes to run when a new root appears; registered by the exported function.
    var shadowListeners = [];

    // Hook `attachShadow` so shadow roots can be discovered at all.
    //
    // A MutationObserver never fires for `attachShadow` — attaching a root to an
    // element that is already in the tree mutates nothing — so root discovery
    // cannot be mutation-driven, and the constructor is the only reliable hook.
    // We capture the *return value* rather than reading `element.shadowRoot`,
    // which is what makes closed roots reachable: `shadowRoot` is null for those,
    // and closed roots are exactly where consent banners and ad containers like
    // to sit.
    //
    // Patching a page prototype is observable to the page — a script can compare
    // `Element.prototype.attachShadow.toString()`, or hold a reference taken
    // before we ran. That is a knowing tradeoff: there is no unobservable
    // equivalent, and without it a whole class of filters silently does nothing.
    // The wrapper therefore delegates to the native method untouched and returns
    // its result verbatim, so the only observable difference is its source text.
    function installShadowHook(win) {
        var proto;
        try {
            proto = win.Element ? win.Element.prototype : null;
        } catch (err) {
            return;
        }
        if (!proto || !proto.attachShadow || proto.attachShadow.__privaxyHooked) {
            return;
        }
        var native = proto.attachShadow;
        var patched = function attachShadow() {
            var root = native.apply(this, arguments);
            try {
                shadowRoots.add(root);
                // Nothing observes this root yet and its creation produced no
                // mutation record anywhere, so without an explicit nudge content
                // written into it would stay unfiltered until some unrelated
                // mutation happened to schedule a pass.
                for (var i = 0; i < shadowListeners.length; i++) {
                    shadowListeners[i]();
                }
            } catch (err) {
                /* never let bookkeeping break the page's own attachShadow */
            }
            return root;
        };
        patched.__privaxyHooked = true;
        try {
            proto.attachShadow = patched;
        } catch (err) {
            /* frozen prototype: fall back to the open-root sweep */
        }
    }

    installShadowHook(window);

    // The shadow roots belonging to one scope: those whose host sits directly in
    // `node`'s tree. `contains` does not cross shadow boundaries, so a root
    // nested inside another root is attributed to the inner scope instead and is
    // picked up when the walk recurses into it.
    //
    // `sweep` additionally scans for `element.shadowRoot`, which finds open roots
    // the hook never saw: `<template shadowrootmode>` roots are built by the
    // parser without calling `attachShadow` at all, as are any roots created
    // before the hook was installed in that window. The scan is O(elements), so
    // callers gate it on a mutation having actually added element nodes.
    function collectShadowRoots(node, sweep) {
        var out = [];
        var stale = null;
        shadowRoots.forEach(function (root) {
            var host = root.host;
            if (!host) {
                return;
            }
            // A root whose host has left the document is unreachable, and this
            // registry holds strong references — dropping it is what keeps a
            // long-lived page from retaining every detached tree it ever built.
            // A host detached and later re-attached loses its registration; the
            // sweep re-finds it if the root is open.
            if (!host.isConnected) {
                if (connectedRoots.has(root)) {
                    (stale || (stale = [])).push(root);
                }
                return;
            }
            connectedRoots.add(root);
            if (node.contains(host)) {
                out.push(root);
            }
        });
        if (stale !== null) {
            for (var s = 0; s < stale.length; s++) {
                shadowRoots.delete(stale[s]);
            }
        }
        if (sweep) {
            var elements = node.querySelectorAll("*");
            for (var i = 0; i < elements.length; i++) {
                var open = elements[i].shadowRoot;
                if (open && !shadowRoots.has(open)) {
                    shadowRoots.add(open);
                    out.push(open);
                }
            }
        }
        return out;
    }

    // Build a string predicate from a uBO argument.
    //   mode "substring" — plain text is a substring test (:has-text, path)
    //   mode "wildcard"  — plain text supports `*` wildcards, full match
    // A `/pattern/flags` argument is always treated as a regular expression.
    function makeMatcher(arg, mode) {
        var m = REGEX_LITERAL.exec(arg);
        if (m !== null) {
            var re = new RegExp(m[1], m[2]);
            return function (value) {
                return re.test(value);
            };
        }
        if (mode === "wildcard") {
            var escaped = arg.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
            var wild = new RegExp("^" + escaped + "$");
            return function (value) {
                return wild.test(value);
            };
        }
        return function (value) {
            return value.indexOf(arg) !== -1;
        };
    }

    function uniqueElements(nodes) {
        var seen = new Set();
        var out = [];
        for (var i = 0; i < nodes.length; i++) {
            var node = nodes[i];
            if (node && node.nodeType === 1 && !seen.has(node)) {
                seen.add(node);
                out.push(node);
            }
        }
        return out;
    }

    function matchesCss(scope, node, arg, pseudo) {
        var sep = arg.indexOf(":");
        if (sep === -1) {
            return false;
        }
        var prop = arg.slice(0, sep).trim();
        var matcher = makeMatcher(arg.slice(sep + 1).trim(), "wildcard");
        var style = scope.win.getComputedStyle(node, pseudo || null);
        return matcher(style.getPropertyValue(prop).trim());
    }

    function matchesAttr(node, arg) {
        var sep = arg.indexOf("=");
        var nameArg = sep === -1 ? arg : arg.slice(0, sep);
        var nameMatcher = makeMatcher(nameArg.trim(), "wildcard");
        var valueMatcher = null;
        if (sep !== -1) {
            var rawValue = arg.slice(sep + 1).trim().replace(/^["']|["']$/g, "");
            valueMatcher = makeMatcher(rawValue, "wildcard");
        }
        var attrs = node.attributes;
        for (var i = 0; i < attrs.length; i++) {
            if (nameMatcher(attrs[i].name)) {
                if (valueMatcher === null || valueMatcher(attrs[i].value)) {
                    return true;
                }
            }
        }
        return false;
    }

    // `parentElement` and `closest` both stop at a shadow boundary rather than
    // hopping to `getRootNode().host`. That is deliberate: uBO's `:upward` climbs
    // within one tree, and a rule written against a page's light DOM must not
    // suddenly be able to reach out of a root and hide the host's ancestors.
    function climbUpward(node, arg) {
        var steps = parseInt(arg, 10);
        if (String(steps) === arg.trim()) {
            var current = node;
            while (steps-- > 0 && current !== null) {
                current = current.parentElement;
            }
            return current;
        }
        return node.parentElement !== null ? node.parentElement.closest(arg) : null;
    }

    function evaluateXpath(scope, contextNode, arg) {
        var result = scope.doc.evaluate(
            arg,
            contextNode,
            null,
            XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
            null
        );
        var out = [];
        for (var i = 0; i < result.snapshotLength; i++) {
            out.push(result.snapshotItem(i));
        }
        return out;
    }

    // Apply one operator to the running node set within `scope` (a
    // {doc, win, isShadow} triple, where `doc` may be a ShadowRoot and `win` is
    // always the window hosting it). `nodes` is null until the first selector
    // seeds it from the scope root.
    function applyOperator(scope, nodes, op) {
        var arg = op.arg;
        switch (op.type) {
            case "css-selector":
                if (nodes === null) {
                    return Array.prototype.slice.call(scope.doc.querySelectorAll(arg));
                }
                return nodes.reduce(function (acc, node) {
                    return acc.concat(Array.prototype.slice.call(node.querySelectorAll(arg)));
                }, []);
            case "has-text": {
                var textMatcher = makeMatcher(arg, "substring");
                return (nodes || []).filter(function (node) {
                    return textMatcher(node.textContent || "");
                });
            }
            case "min-text-length": {
                var minLength = parseInt(arg, 10);
                return (nodes || []).filter(function (node) {
                    return (node.textContent || "").length >= minLength;
                });
            }
            case "matches-path": {
                var pathMatcher = makeMatcher(arg, "substring");
                var path = scope.win.location.pathname + scope.win.location.search;
                return pathMatcher(path) ? (nodes || []) : [];
            }
            case "matches-css":
                return (nodes || []).filter(function (node) {
                    return matchesCss(scope, node, arg, null);
                });
            case "matches-css-before":
                return (nodes || []).filter(function (node) {
                    return matchesCss(scope, node, arg, "::before");
                });
            case "matches-css-after":
                return (nodes || []).filter(function (node) {
                    return matchesCss(scope, node, arg, "::after");
                });
            case "matches-attr":
                return (nodes || []).filter(function (node) {
                    return matchesAttr(node, arg);
                });
            case "upward":
                return uniqueElements((nodes || []).map(function (node) {
                    return climbUpward(node, arg);
                }));
            case "xpath":
                // `ShadowRoot` has no `evaluate`, and XPath across a shadow
                // boundary has no defined behaviour — engines disagree on whether
                // a shadow tree is even addressable. Evaluating against
                // `scope.doc.ownerDocument` would silently either match nothing
                // or match nodes outside the scope, depending on the browser, so
                // `xpath` simply selects nothing inside a root.
                if (scope.isShadow) {
                    return [];
                }
                if (nodes === null) {
                    return evaluateXpath(scope, scope.doc, arg);
                }
                return uniqueElements((nodes || []).reduce(function (acc, node) {
                    return acc.concat(evaluateXpath(scope, node, arg));
                }, []));
            default:
                return nodes || [];
        }
    }

    function selectNodes(scope, selector) {
        var nodes = null;
        for (var i = 0; i < selector.length; i++) {
            nodes = applyOperator(scope, nodes, selector[i]);
            if (nodes !== null && nodes.length === 0) {
                return [];
            }
        }
        return uniqueElements(nodes || []);
    }

    function applyStyle(node, declarations) {
        declarations.split(";").forEach(function (declaration) {
            var sep = declaration.indexOf(":");
            if (sep === -1) {
                return;
            }
            var prop = declaration.slice(0, sep).trim();
            var value = declaration.slice(sep + 1).trim();
            var priority = "";
            if (/!important$/.test(value)) {
                value = value.replace(/!important$/, "").trim();
                priority = "important";
            }
            if (prop !== "") {
                node.style.setProperty(prop, value, priority);
            }
        });
    }

    function applyAction(node, action) {
        if (!action) {
            node.style.setProperty("display", "none", "important");
            return;
        }
        switch (action.type) {
            case "style":
                applyStyle(node, action.arg);
                break;
            case "remove":
                node.remove();
                break;
            case "remove-attr":
                node.removeAttribute(action.arg);
                break;
            case "remove-class":
                node.classList.remove(action.arg);
                break;
        }
    }

    return function (filters, expectCosmeticCss) {
        var rules = Array.isArray(filters) ? filters : [];
        if (rules.length === 0 && expectCosmeticCss !== true) {
            return;
        }

        var scheduled = false;
        // Armed for the first pass: declarative shadow roots already exist by the
        // time we run, and no mutation will ever announce them.
        var needSweep = true;
        var observedRoots = new WeakSet();

        // Walk this window and every reachable same-origin descendant frame and
        // shadow root, returning a {doc, win, isShadow} scope for each.
        // Cross-origin frames throw on document access and are skipped.
        //
        // Shadow roots recurse exactly like frames, so every nesting combination
        // — a root in a root, a frame in a root, a root in a frame — falls out of
        // the recursion with no special case. Querying frames from each scope
        // root also fixes an iframe inside a shadow root being invisible to the
        // old document-only `querySelectorAll("iframe, frame")`.
        //
        // For a shadow scope, `win` stays the *host* window: that is what
        // `getComputedStyle` and `matches-path` need, and a root has no window of
        // its own.
        function collectScopes(sweep) {
            var scopes = [];
            var seen = new Set();

            function visit(win, node, isShadow) {
                if (!node || seen.has(node)) {
                    return;
                }
                seen.add(node);
                scopes.push({ doc: node, win: win, isShadow: isShadow });

                var frames = node.querySelectorAll("iframe, frame");
                for (var i = 0; i < frames.length; i++) {
                    var childWin = null;
                    try {
                        childWin = frames[i].contentWindow;
                    } catch (err) {
                        childWin = null;
                    }
                    if (childWin) {
                        visitWindow(childWin);
                    }
                }

                var roots = collectShadowRoots(node, sweep);
                for (var j = 0; j < roots.length; j++) {
                    visit(win, roots[j], true);
                }
            }

            function visitWindow(win) {
                var doc;
                try {
                    doc = win.document;
                } catch (err) {
                    return;
                }
                // A same-origin frame has its own `Element.prototype`, so it
                // needs its own hook. Roots it created before this first visit
                // are only found by the sweep, i.e. only if they're open.
                installShadowHook(win);
                visit(win, doc, false);
            }

            visitWindow(window);
            return scopes;
        }

        // The plain-CSS cosmetic rules, read back out of the block the proxy
        // appends at end-of-body (marked with `data-privaxy-cosmetics`; the
        // attribute name is authored in `html_rewriter.rs`).
        //
        // Reading the block rather than receiving the CSS as an argument keeps it
        // from being serialized into the page twice — on a typical host the block
        // is ~36 KB — and it means roots also get the class/id-indexed generic
        // selectors, which only exist in the end-of-body lookup because they are
        // derived from the IDs and classes found while parsing the document.
        //
        // The cost is timing: the block arrives after this shim has already run,
        // so roots stay unstyled until it does. That is the same moment the
        // document itself gets styled, so roots are never behind the light DOM.
        // Our own observer sees the block inserted and schedules the pass that
        // picks it up.
        var cssText = null;

        function cosmeticCss() {
            if (cssText !== null) {
                return cssText;
            }
            var block = document.querySelector("style[data-privaxy-cosmetics]");
            if (block === null) {
                return "";
            }
            var text = block.textContent || "";
            // An empty block means this host has no plain rules. It can also mean
            // the element is in the tree but its text has not been parsed yet, so
            // this stays uncached and is retried on the next pass either way.
            if (text.trim() === "") {
                return "";
            }
            cssText = text;
            return cssText;
        }

        // One constructed stylesheet per document, shared by every shadow root in
        // it. It has to be per document rather than a single global sheet: a
        // constructed stylesheet is bound to the document that created it, and
        // adopting one into a root belonging to a different document throws.
        // `null` records a document where construction isn't available, so the
        // fallback is chosen once instead of being retried on every pass.
        var sheets = new WeakMap();
        var styledRoots = new WeakSet();

        function cosmeticSheet(win, css) {
            var doc = win.document;
            if (sheets.has(doc)) {
                return sheets.get(doc);
            }
            var sheet = null;
            try {
                sheet = new win.CSSStyleSheet();
                sheet.replaceSync(css);
            } catch (err) {
                sheet = null;
            }
            sheets.set(doc, sheet);
            return sheet;
        }

        // Deliver the plain-CSS rules into one shadow root.
        //
        // `adoptedStyleSheets` is preferred over appending a <style>: adopting
        // adds no node, so there is nothing for page scripts to notice and
        // nothing for our own observer to report — which also means it cannot
        // schedule another pass.
        function deliverCss(scope) {
            if (!scope.isShadow || styledRoots.has(scope.doc)) {
                return;
            }
            // Not marking the root as styled means a root visited before the block
            // arrived is picked up on the pass that the block's insertion triggers.
            var css = cosmeticCss();
            if (css === "") {
                return;
            }
            var root = scope.doc;
            var sheet = cosmeticSheet(scope.win, css);
            if (sheet !== null) {
                var adopted = root.adoptedStyleSheets;
                // Assign a new array rather than pushing: `adoptedStyleSheets` is
                // a frozen array in the original implementations.
                if (adopted.indexOf(sheet) === -1) {
                    root.adoptedStyleSheets = adopted.concat(sheet);
                }
                styledRoots.add(root);
                return;
            }
            // No constructable stylesheets. A <style> *inside* a root does apply
            // to that root's tree, so this is correct, just noisier: it is one
            // extra node, and inserting it schedules one further pass — which
            // then finds the root already in `styledRoots` and settles.
            var style = scope.win.document.createElement("style");
            if (injectedNonce !== "") {
                style.setAttribute("nonce", injectedNonce);
                style.nonce = injectedNonce;
            }
            style.textContent = css;
            root.appendChild(style);
            styledRoots.add(root);
        }

        // Ads are often written into a frame or a shadow root *after* it's
        // created, and an observer never sees mutations inside a child document
        // or across a shadow boundary, so every scope gets its own observer
        // (once). `ShadowRoot` is a valid `observe()` target and has no
        // `documentElement`, so the fallback lands on the root itself.
        function ensureObserved(root) {
            if (observedRoots.has(root)) {
                return;
            }
            observedRoots.add(root);
            var observer = new MutationObserver(onMutations);
            observer.observe(root.documentElement || root, { childList: true, subtree: true });
        }

        function apply() {
            scheduled = false;
            var sweep = needSweep;
            needSweep = false;
            var scopes = collectScopes(sweep);
            for (var s = 0; s < scopes.length; s++) {
                var scope = scopes[s];
                ensureObserved(scope.doc);
                // Wrapped for the same reason the rules below are: a root can be
                // detached, or its document torn down, between scope collection
                // and here.
                try {
                    deliverCss(scope);
                } catch (err) {
                    /* this root goes unstyled; carry on with the rest */
                }
                for (var i = 0; i < rules.length; i++) {
                    // A single malformed rule (or a frame torn down mid-pass)
                    // must not break the rest; throwing is part of normal
                    // operation here.
                    try {
                        var nodes = selectNodes(scope, rules[i].selector);
                        for (var j = 0; j < nodes.length; j++) {
                            applyAction(nodes[j], rules[i].action);
                        }
                    } catch (err) {
                        /* ignore this rule and continue */
                    }
                }
            }
        }

        // Observers only feed `childList` mutations, so our hide/style/attr
        // edits don't loop; a `:remove()` converges in one extra debounced pass.
        function schedule() {
            if (scheduled) {
                return;
            }
            scheduled = true;
            window.requestAnimationFrame(apply);
        }

        function scheduleSweep() {
            needSweep = true;
            schedule();
        }

        function addedElements(records) {
            for (var i = 0; i < records.length; i++) {
                var added = records[i].addedNodes;
                for (var j = 0; j < added.length; j++) {
                    if (added[j].nodeType === 1) {
                        return true;
                    }
                }
            }
            return false;
        }

        // An added element can carry a declarative shadow root or be handed one
        // later, so that — and only that — arms the next pass's sweep. Passes
        // triggered by anything else stay O(rules).
        function onMutations(records) {
            if (addedElements(records)) {
                needSweep = true;
            }
            schedule();
        }

        shadowListeners.push(schedule);

        scheduleSweep();
        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", scheduleSweep);
        }
    };
})();
