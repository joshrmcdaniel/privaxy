/*
 * Privaxy in-page procedural cosmetic filtering shim.
 *
 * The proxy can apply plain-CSS cosmetic rules server-side by injecting a
 * <style> block, but uBO/AdGuard procedural rules (:has-text, :matches-css,
 * :upward, :xpath, :remove(), …) need to be evaluated against the live DOM.
 * This shim receives those rules as JSON and applies them on load and on every
 * subsequent DOM mutation.
 *
 * Rules are evaluated against the top document AND every reachable child-frame
 * document. Same-origin frames built without a network fetch (`about:blank`,
 * `srcdoc`, `data:`) never reach the proxy, so the only way to filter their
 * contents is from the parent page — which we can do whenever the frame is
 * same-origin (e.g. a `sandbox` that includes `allow-same-origin`). Cross-origin
 * frames throw on document access and are silently skipped (those are filtered
 * via their own proxied response instead).
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

    // Apply one operator to the running node set within `scope` (a {doc, win}
    // pair). `nodes` is null until the first selector seeds it from the document.
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

    return function (filters) {
        if (!Array.isArray(filters) || filters.length === 0) {
            return;
        }

        var scheduled = false;
        var observedDocs = new WeakSet();

        // Walk this window and every reachable same-origin descendant frame,
        // returning a {doc, win} scope for each. Cross-origin frames throw on
        // document access and are skipped.
        function collectScopes() {
            var scopes = [];
            var seenDocs = new Set();
            (function visit(win) {
                var doc;
                try {
                    doc = win.document;
                } catch (err) {
                    return;
                }
                if (!doc || seenDocs.has(doc)) {
                    return;
                }
                seenDocs.add(doc);
                scopes.push({ doc: doc, win: win });
                var frames = doc.querySelectorAll("iframe, frame");
                for (var i = 0; i < frames.length; i++) {
                    var childWin = null;
                    try {
                        childWin = frames[i].contentWindow;
                    } catch (err) {
                        childWin = null;
                    }
                    if (childWin) {
                        visit(childWin);
                    }
                }
            })(window);
            return scopes;
        }

        // Ads are often written into a frame *after* it's created, and a
        // parent's observer doesn't see mutations inside a child document, so
        // each reachable frame document gets its own observer (once).
        function ensureObserved(doc) {
            if (observedDocs.has(doc)) {
                return;
            }
            observedDocs.add(doc);
            var observer = new MutationObserver(schedule);
            observer.observe(doc.documentElement || doc, { childList: true, subtree: true });
        }

        function apply() {
            scheduled = false;
            var scopes = collectScopes();
            for (var s = 0; s < scopes.length; s++) {
                var scope = scopes[s];
                ensureObserved(scope.doc);
                for (var i = 0; i < filters.length; i++) {
                    // A single malformed rule (or a frame torn down mid-pass)
                    // must not break the rest; throwing is part of normal
                    // operation here.
                    try {
                        var nodes = selectNodes(scope, filters[i].selector);
                        for (var j = 0; j < nodes.length; j++) {
                            applyAction(nodes[j], filters[i].action);
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

        schedule();
        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", schedule);
        }
    };
})();
