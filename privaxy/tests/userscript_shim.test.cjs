const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

test('GM endpoints receive the capability for the requesting script', async () => {
    const requests = [];
    let poll;
    const context = vm.createContext({
        PRIVAXY_NONCE: 'fixture-nonce',
        PRIVAXY_ENDPOINT_TOKENS: { 'a.user.js': 'token-a', 'b.user.js': 'token-b' },
        window: {},
        document: { currentScript: { textContent: 'fixture' } },
        location: { href: 'https://example.com/watch' },
        URL,
        console,
        setInterval(callback) { poll = callback; return 1; },
        fetch: async (url, options) => {
            requests.push({ url, body: JSON.parse(options.body) });
            return { ok: true, json: async () => ({ values: {} }) };
        },
    });
    const source = readFileSync(
        join(__dirname, '../src/resources/userscript_shim.js'), 'utf8'
    );
    vm.runInContext(source, context);

    for (const [script, token] of [['a.user.js', 'token-a'], ['b.user.js', 'token-b']]) {
        const api = context.privaxyBuildApi({
            id: script, name: script, values: {}, resources: { icon: {} },
        });
        api.GM_setValue('theme', 'dark');
        api.GM_addValueChangeListener('theme', () => {});
        api.GM_xmlhttpRequest({ url: '/fixture' });
        const resource = new URL(api.GM_getResourceURL('icon'), context.location.href);
        assert.equal(resource.searchParams.get('script'), script);
        assert.equal(resource.searchParams.get('token'), token);
    }
    await new Promise(resolve => setImmediate(resolve));
    poll();
    await new Promise(resolve => setImmediate(resolve));

    for (const endpoint of ['values', 'read', 'fetch']) {
        const calls = requests.filter(request => request.url.endsWith('/' + endpoint));
        assert.equal(calls.length, 2, endpoint);
        for (const call of calls) {
            assert.equal(call.body.token, context.PRIVAXY_ENDPOINT_TOKENS[call.body.script]);
        }
    }

    const unknown = context.privaxyBuildApi({ id: 'other.user.js', name: 'Other', resources: { icon: {} } });
    const before = requests.length;
    unknown.GM_setValue('theme', 'light');
    unknown.GM_addValueChangeListener('theme', () => {});
    poll();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(unknown.GM_getResourceURL('icon'), null);
    assert.throws(() => unknown.GM_xmlhttpRequest({ url: '/fixture' }), /unavailable/);
    assert.equal(requests.length, before + 2); // Only the two authorized scripts poll.
});
