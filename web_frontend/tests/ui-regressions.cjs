// Browser regression checks against a built frontend with a deterministic API.
// Install Playwright separately, then run with it on NODE_PATH:
//   NODE_PATH=/path/to/node_modules node web_frontend/tests/ui-regressions.cjs
// Optional: PRIVAXY_UI_DIST, PRIVAXY_UI_BROWSER, PRIVAXY_UI_SCREENSHOTS.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require('playwright');
const dist = path.resolve(process.env.PRIVAXY_UI_DIST || 'web_frontend/dist');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function eventually(check, message) {
    const deadline = Date.now() + 4000;
    while (Date.now() < deadline) {
        if (await check()) return;
        await delay(40);
    }
    assert.fail(message);
}
const sampleFilter = (title, enabled = true) => ({
    title, enabled, group: 'Ads', file_name: `${title}.txt`,
    url: `https://example.test/${encodeURIComponent(title)}.txt`, is_default: false,
});
const catalog = Array.from({ length: 24 }, (_, i) => ({
    id: i + 1, name: `Catalog list ${String(i + 1).padStart(2, '0')}`,
    description: 'Test filter list', licenseId: 1, syntaxIds: [],
    languageIds: [], tagIds: [], maintainerIds: [],
}));
const statistics = { proxied_requests: 12, blocked_requests: 4, modified_responses: 2, top_blocked_paths: {}, top_clients: {} };
const tests = [];
const test = (name, fn) => tests.push({ name, fn });

async function fixture(browser, viewport = { width: 1280, height: 900 }) {
    const context = await browser.newContext({ viewport });
    const page = await context.newPage();
    page.setDefaultTimeout(4000);
    const handlers = new Map();
    const calls = [];
    const sockets = {};
    const errors = [];
    const state = { filters: [sampleFilter('Existing list')], blocking: true, text: '! saved rules' };
    page.on('pageerror', error => errors.push(error.message));
    await page.routeWebSocket('**/api/**', ws => {
        const resource = new URL(ws.url()).pathname;
        (sockets[resource] ||= []).push(ws);
        if (resource === '/api/statistics') ws.send(JSON.stringify(statistics));
    });
    await page.route('**/*', async route => {
        const request = route.request();
        const resource = new URL(request.url()).pathname;
        const key = `${request.method()} ${resource}`;
        if (resource.startsWith('/api/')) {
            calls.push({ key, body: request.postData() });
            let result;
            if (handlers.has(key)) {
                result = await handlers.get(key)(request);
            } else if (resource === '/api/auth/status') {
                result = { authenticated: true, setup_required: false, username: 'tester' };
            } else if (resource === '/api/auth/api-key') {
                result = { api_key: 'fixture-key' };
            } else if (resource === '/api/blocking-enabled') {
                if (request.method() === 'PUT') state.blocking = request.postDataJSON();
                result = state.blocking;
            } else if (resource === '/api/filters') {
                if (request.method() === 'POST') state.filters.push(sampleFilter(request.postDataJSON().title));
                if (request.method() === 'PUT') {
                    for (const selection of request.postDataJSON()) {
                        state.filters.find(f => f.file_name === selection.file_name).enabled = selection.enabled;
                    }
                }
                if (request.method() === 'DELETE') state.filters = state.filters.filter(f => f.title !== request.postDataJSON().title);
                result = state.filters;
            } else if (resource === '/api/filterlists/list') {
                result = catalog;
            } else if (/^\/api\/filterlists\/list\/\d+$/.test(resource)) {
                const filter = catalog[Number(resource.split('/').at(-1)) - 1];
                result = { ...filter, viewUrls: [{ segmentNumber: 1, primariness: 1, url: `https://example.test/catalog-${filter.id}.txt` }] };
            } else if (resource.startsWith('/api/filterlists/') || resource === '/api/filters/failures' || resource === '/api/tls-failures') {
                result = [];
            } else if (resource === '/api/custom-filters' || resource === '/api/exclusions') {
                if (request.method() === 'PUT') state.text = request.postDataJSON();
                result = state.text;
            } else if (resource === '/api/exclusions/defaults') {
                result = 'default.example.test';
            } else if (resource === '/api/userscripts') {
                result = { enabled: false, allow_private_network_requests: false, scripts: [] };
            } else if (resource === '/api/inclusions') {
                result = { include_only: false, inclusions: [] };
            } else if (resource === '/api/settings/network') {
                result = { bind_addr: '127.0.0.1', proxy_port: 8100, web_port: 8200, tls: false, doh: { mode: 'block' } };
            } else if (resource === '/api/settings/pac') {
                result = { pac_enabled: false, pac_direct_ips: [], pac_direct_cidrs: {}, pac_direct_fqdns: [] };
            } else if (resource === '/api/settings/debug') {
                result = { scriptlet_console_logging: false, log_level: 'info' };
            } else {
                result = { status: 404, json: { error: `No fixture for ${key}` } };
            }
            const wrapped = result && typeof result === 'object' && 'status' in result;
            await route.fulfill(wrapped ? (result.body !== undefined ? { status: result.status, body: result.body, contentType: result.contentType || 'text/plain' } : { status: result.status, json: result.json }) : { status: 200, json: result }).catch(() => {});
            return;
        }
        let file = path.resolve(dist, `.${resource}`);
        if (!file.startsWith(`${dist}${path.sep}`)) file = path.join(dist, 'index.html');
        try {
            if (!(await fs.stat(file)).isFile()) file = path.join(dist, 'index.html');
        } catch {
            file = path.join(dist, 'index.html');
        }
        const types = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.css': 'text/css', '.svg': 'image/svg+xml' };
        await route.fulfill({ body: await fs.readFile(file), contentType: types[path.extname(file)] || 'application/octet-stream' });
    });
    return { page, context, handlers, state, calls, sockets, errors, async go(route) {
        await page.goto(`http://privaxy.test${route}`);
        await page.getByRole('button', { name: 'Sign out' }).waitFor();
    } };
}

const saveButton = page => page.getByRole('button', { name: 'Save changes', exact: true });
const failure = { status: 500, json: { error: 'Disk write failed' } };

test('unchanged text settings have a disabled Save button', async f => {
    await f.go('/settings/custom-filters');
    await eventually(async () => await f.page.locator('textarea').inputValue() === f.state.text, 'rules did not load');
    assert(await saveButton(f.page).isDisabled());
});

test('failed text save keeps the draft and allows retry', async f => {
    f.handlers.set('PUT /api/custom-filters', async () => failure);
    await f.go('/settings/custom-filters');
    await f.page.locator('textarea').fill('||new.example.test^');
    await saveButton(f.page).click();
    await f.page.getByRole('alert').filter({ hasText: 'Disk write failed' }).waitFor();
    assert.equal(await f.page.locator('textarea').inputValue(), '||new.example.test^');
    assert(await saveButton(f.page).isEnabled());
    assert.equal(await f.page.getByText('Changes saved', { exact: true }).count(), 0);
    f.handlers.delete('PUT /api/custom-filters');
    await saveButton(f.page).click();
    await f.page.getByText('Changes saved', { exact: true }).waitFor();
});

test('edits made during a text save remain unsaved', async f => {
    f.handlers.set('PUT /api/custom-filters', async request => {
        await delay(400);
        f.state.text = request.postDataJSON();
        return '';
    });
    await f.go('/settings/custom-filters');
    await f.page.locator('textarea').fill('first draft');
    await saveButton(f.page).click();
    await f.page.getByRole('button', { name: 'Loading...' }).waitFor();
    await f.page.locator('textarea').fill('second draft');
    await eventually(() => saveButton(f.page).isEnabled(), 'new draft was incorrectly marked saved');
    assert.equal(f.state.text, 'first draft');
    assert.equal(await f.page.locator('textarea').inputValue(), 'second draft');
    assert.equal(await f.page.getByText('Changes saved', { exact: true }).count(), 0);
});

for (const [name, resource, route, retry] of [
    ['text settings', '/api/custom-filters', '/settings/custom-filters', 'Retry loading settings'],
    ['filters', '/api/filters', '/settings/filters', 'Retry loading filters'],
    ['network settings', '/api/settings/network', '/settings/general', 'Retry loading network settings'],
    ['PAC settings', '/api/settings/pac', '/settings/pac', 'Retry loading PAC settings'],
    ['debug settings', '/api/settings/debug', '/settings/debug', 'Retry loading debug settings'],
    ['API key', '/api/auth/api-key', '/settings/account', 'Retry loading API key'],
    ['inclusions', '/api/inclusions', '/settings/exclusions', 'Retry loading inclusions'],
]) {
    test(`${name} load errors are visible and retryable`, async f => {
        f.handlers.set(`GET ${resource}`, async () => failure);
        await f.go(route);
        await f.page.getByRole('alert').filter({ hasText: 'Disk write failed' }).waitFor();
        f.handlers.delete(`GET ${resource}`);
        await f.page.getByRole('button', { name: retry }).click();
        await eventually(async () => await f.page.getByRole('alert').count() === 0, 'load did not recover');
    });
}

test('filter labels toggle their checkbox and failed saves stay dirty', async f => {
    f.handlers.set('PUT /api/filters', async () => failure);
    await f.go('/settings/filters');
    await f.page.getByText('Existing list', { exact: true }).click();
    assert.equal(await f.page.locator('input[type=checkbox]').first().isChecked(), false);
    await saveButton(f.page).click();
    await f.page.getByRole('alert').filter({ hasText: 'Disk write failed' }).waitFor();
    assert(await saveButton(f.page).isEnabled());
});

test('adding a filter refreshes the list and preserves pending selections', async f => {
    await f.go('/settings/filters');
    await f.page.locator('input[type=checkbox]').first().uncheck();
    await f.page.getByRole('button', { name: 'Add filter', exact: true }).click();
    const dialog = f.page.locator('.fixed.inset-0');
    await dialog.locator('input').nth(0).fill('New fixture list');
    await dialog.locator('input').nth(1).fill('https://example.test/new.txt');
    await dialog.getByRole('button', { name: 'Save', exact: true }).click();
    await f.page.getByText('New fixture list', { exact: true }).waitFor();
    assert.equal(await f.page.locator('input[type=checkbox]').first().isChecked(), false);
    assert(await saveButton(f.page).isEnabled());
});

test('search resets pagination and disables Next with no matches', async f => {
    await f.go('/settings/filters');
    await f.page.getByRole('button', { name: 'Search filterlists.com' }).click();
    await f.page.getByText('Catalog list 01', { exact: true }).waitFor();
    await f.page.getByRole('button', { name: 'Next', exact: true }).click();
    await f.page.getByPlaceholder('Search by name').fill('Catalog list 01');
    await f.page.getByText('Catalog list 01', { exact: true }).waitFor();
    assert(await f.page.getByRole('button', { name: 'Next', exact: true }).isDisabled());
    await f.page.getByPlaceholder('Search by name').fill('missing name');
    assert(await f.page.getByRole('button', { name: 'Next', exact: true }).isDisabled());
});

test('failed catalog removal leaves the installed list visible', async f => {
    f.state.filters = [sampleFilter('Catalog list 01')];
    f.handlers.set('DELETE /api/filters', async () => failure);
    await f.go('/settings/filters');
    await f.page.getByRole('button', { name: 'Search filterlists.com' }).click();
    await f.page.getByRole('button', { name: 'Remove', exact: true }).click();
    await f.page.getByRole('alert').filter({ hasText: 'Disk write failed' }).waitFor();
    assert(await f.page.getByRole('button', { name: 'Remove', exact: true }).isEnabled());
});

for (const [name, route, resource, message] of [
    ['requests', '/requests', '/api/events', { now: '12:00:00', method: 'GET', url: 'https://example.test/reconnected', is_request_blocked: true }],
    ['logs', '/settings/debug', '/api/logs', { now: '12:00:00', level: 'INFO', target: 'fixture', message: 'reconnected log entry' }],
    ['statistics', '/', '/api/statistics', { ...statistics, blocked_requests: 9876 }],
]) {
    test(`${name} reconnect after disconnect and ignore malformed frames`, async f => {
        await f.go(route);
        await eventually(() => f.sockets[resource]?.length === 1, 'initial websocket missing');
        f.sockets[resource][0].close({ code: 1012, reason: 'fixture restart' });
        await eventually(() => f.sockets[resource]?.length === 2, 'websocket did not reconnect');
        const ws = f.sockets[resource][1];
        ws.send('invalid json');
        ws.send(Buffer.from([1, 2, 3]));
        ws.send(JSON.stringify(message));
        await f.page.getByText(name === 'requests' ? message.url : name === 'logs' ? message.message : '9,876', { exact: true }).waitFor();
        // Leaving the page must cancel reconnect attempts as well.
        await f.page.getByRole('link', { name: 'Settings', exact: true }).click();
        await delay(1200);
        assert.equal(f.sockets[resource].length, 2);
    });
}

test('blocking toggle recovers from a failed update without changing its state', async f => {
    f.handlers.set('PUT /api/blocking-enabled', async () => failure);
    await f.go('/');
    await f.page.getByRole('button', { name: 'Pause blocking' }).click();
    await f.page.getByRole('alert').filter({ hasText: 'Disk write failed' }).waitFor();
    assert(await f.page.getByRole('button', { name: 'Pause blocking' }).isEnabled());
    f.handlers.delete('PUT /api/blocking-enabled');
    await f.page.getByRole('button', { name: 'Pause blocking' }).click();
    await f.page.getByRole('button', { name: 'Resume blocking' }).waitFor();
});

test('PAC save locks fields until the submitted values are acknowledged', async f => {
    f.handlers.set('PUT /api/settings/pac', async () => { await delay(350); return ''; });
    await f.go('/settings/pac');
    const input = f.page.getByPlaceholder('e.g. 192.168.1.10:8100');
    await input.fill('proxy.example.test:8100');
    await saveButton(f.page).click();
    assert(await input.isDisabled());
    await f.page.getByText('Changes saved', { exact: true }).waitFor();
    assert(await saveButton(f.page).isDisabled());
});

test('general settings recover from non-JSON save errors', async f => {
    f.handlers.set('PUT /api/settings/network', async () => ({ status: 502, body: '<h1>Bad Gateway</h1>', contentType: 'text/html' }));
    await f.go('/settings/general');
    await f.page.locator('input[type=text]').nth(3).fill('http://proxy.example.test');
    await saveButton(f.page).click();
    await f.page.getByRole('alert').filter({ hasText: 'HTTP 502' }).waitFor();
    assert(await saveButton(f.page).isEnabled());
});

test('failed automatic debug saves restore the confirmed value', async f => {
    f.handlers.set('PUT /api/settings/debug', async () => failure);
    await f.go('/settings/debug');
    await f.page.locator('select').first().selectOption('debug');
    await f.page.getByRole('alert').waitFor();
    assert.equal(await f.page.locator('select').first().inputValue(), 'info');
});

test('authentication service failures show a retry instead of a login form', async f => {
    f.handlers.set('GET /api/auth/status', async () => failure);
    await f.page.goto('http://privaxy.test/');
    await f.page.getByRole('alert').waitFor();
    f.handlers.delete('GET /api/auth/status');
    await f.page.getByRole('button', { name: 'Retry', exact: true }).click();
    await f.page.getByRole('button', { name: 'Sign out' }).waitFor();
});

test('userscript loading failures remain retryable', async f => {
    f.handlers.set('GET /api/userscripts', async () => failure);
    await f.go('/settings/userscripts');
    await f.page.getByRole('alert').waitFor();
    // A load failure must not disappear along with a timed success/error banner.
    await delay(4200);
    f.handlers.delete('GET /api/userscripts');
    await f.page.getByRole('button', { name: 'Retry loading userscripts' }).click();
    await f.page.getByText('Installed scripts', { exact: true }).waitFor();
});

test('excluding TLS failures preserves drafts without restoring removed hosts', async f => {
    const failures = ['first.example.test', 'second.example.test'].map(host => ({ host, last_seen: '12:00:00', count: 1, likely_pinning: true, last_error: 'certificate rejected' }));
    f.handlers.set('GET /api/tls-failures', async () => failures);
    f.handlers.set('POST /api/exclusions/add', async request => {
        f.state.text += '\n' + request.postDataJSON();
        return { added: true };
    });
    await f.go('/settings/exclusions');
    await f.page.locator('#exclusions').fill('draft.example.test');
    await f.page.getByRole('button', { name: 'Exclude', exact: true }).first().click();
    await eventually(async () => (await f.page.locator('#exclusions').inputValue()).includes('first.example.test'), 'new exclusion missing from draft');
    await f.page.locator('#exclusions').fill('draft.example.test');
    await f.page.getByRole('button', { name: 'Exclude', exact: true }).click();
    await eventually(async () => (await f.page.locator('#exclusions').inputValue()).includes('second.example.test'), 'second exclusion missing from draft');
    assert.equal(await f.page.locator('#exclusions').inputValue(), 'draft.example.test\nsecond.example.test');
});

test('failed defaults fetch keeps exclusion edits intact', async f => {
    f.handlers.set('GET /api/exclusions/defaults', async () => failure);
    await f.go('/settings/exclusions');
    await f.page.locator('#exclusions').fill('draft.example.test');
    await f.page.getByRole('button', { name: 'Reset to defaults' }).click();
    await f.page.getByRole('alert').filter({ hasText: 'Disk write failed' }).waitFor();
    assert.equal(await f.page.locator('#exclusions').inputValue(), 'draft.example.test');
    f.handlers.delete('GET /api/exclusions/defaults');
    await f.page.getByRole('button', { name: 'Reset to defaults' }).click();
    await eventually(async () => await f.page.locator('#exclusions').inputValue() === 'default.example.test', 'defaults did not load');
    assert.equal(f.state.text, '! saved rules', 'loading defaults must not save automatically');
});

test('phone settings and navigation fit a 375px viewport', async f => {
    await f.page.setViewportSize({ width: 375, height: 812 });
    for (const route of ['/', '/requests', '/settings/general', '/settings/pac', '/settings/debug', '/settings/filters', '/settings/exclusions', '/settings/account', '/settings/userscripts']) {
        await f.go(route);
        await delay(150);
        const width = await f.page.evaluate(() => ({ actual: document.documentElement.scrollWidth, viewport: innerWidth }));
        const overflowing = await f.page.evaluate(() => Array.from(document.querySelectorAll('body *')).filter(e => e.getBoundingClientRect().right > innerWidth + 1).slice(0, 8).map(e => `${e.tagName}.${e.className}`));
        if (process.env.PRIVAXY_UI_SCREENSHOTS) {
            const dir = process.env.PRIVAXY_UI_SCREENSHOTS;
            await fs.mkdir(dir, { recursive: true });
            await f.page.screenshot({ path: path.join(dir, `${route.replaceAll('/', '_') || 'dashboard'}.png`), fullPage: true });
        }
        assert(width.actual <= width.viewport + 1, `${route} overflows: ${JSON.stringify(width)} ${JSON.stringify(overflowing)}`);
    }
});

(async () => {
    const browser = await chromium.launch({ executablePath: process.env.PRIVAXY_UI_BROWSER || undefined, headless: true });
    let failed = 0;
    const selected = tests.filter(test => !process.env.PRIVAXY_UI_TEST || test.name.includes(process.env.PRIVAXY_UI_TEST));
    try {
        for (const { name, fn } of selected) {
            const f = await fixture(browser);
            try {
                await fn(f);
                assert.deepEqual(f.errors, [], 'uncaught browser errors');
                console.log(`PASS ${name}`);
            } catch (error) {
                failed++;
                console.error(`FAIL ${name}: ${error.message}`);
                if (f.errors.length) console.error(f.errors);
            } finally {
                await f.context.close();
            }
        }
    } finally {
        await browser.close();
    }
    console.log(`${selected.length - failed}/${selected.length} browser checks passed`);
    process.exitCode = failed ? 1 : 0;
})().catch(error => { console.error(error); process.exitCode = 1; });
