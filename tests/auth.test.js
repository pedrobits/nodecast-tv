const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const express = require('express');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = 'jwt-secret-for-auth-tests-only';
process.env.SENTRA_HUB_TOKEN = 'sentra-persistent-token-for-auth-tests-only';
process.env.SENTRA_HUB_USERNAME = 'sentra-hub';

const auth = require('../server/auth');
const db = require('../server/db');

test('Sentra sessions and regular logins remain independent', async (t) => {
    const passwordHash = await auth.hashPassword('test-password');
    const integrationUser = { id: 1, username: 'sentra-hub', role: 'viewer', passwordHash };
    const otherUser = { id: 2, username: 'operator', role: 'admin', passwordHash };
    const users = new Map([[1, integrationUser], [2, otherUser]]);
    const originalUsers = db.users;
    db.users = {
        getByUsername: async (username) => [...users.values()].find(user => user.username === username),
        getById: async (id) => users.get(Number(id)),
        getAll: async () => [...users.values()]
    };
    t.after(() => { db.users = originalUsers; });

    const app = express();
    app.use(express.json());
    app.use(auth.passport.initialize());
    app.use('/api/auth', require('../server/routes/auth'));
    let server;
    let baseUrl;
    async function startServer() {
        server = await new Promise((resolve, reject) => {
            const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
            listener.on('error', reject);
        });
        baseUrl = `http://127.0.0.1:${server.address().port}`;
    }
    async function closeServer() {
        await new Promise((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
    }
    await startServer();
    t.after(closeServer);

    const request = (path, token, options = {}) => fetch(`${baseUrl}/api/auth${path}`, {
        ...options,
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }
    });
    const login = (username) => request('/login', null, {
        method: 'POST', body: JSON.stringify({ username, password: 'test-password' })
    });
    const token = process.env.SENTRA_HUB_TOKEN;

    await t.test('password login issues the configured persistent token', async () => {
        const response = await login('sentra-hub');
        assert.equal(response.status, 200);
        assert.equal((await response.json()).token, token);
        assert.equal(jwt.decode(token), null);
        const me = await request('/me', token);
        assert.equal(me.status, 200);
        assert.deepEqual(await me.json(), { id: 1, username: 'sentra-hub', role: 'viewer' });
    });

    await t.test('concurrent launches, other logins and logout do not revoke it', async () => {
        const launches = await Promise.all(Array.from({ length: 5 }, () => request('/me', token)));
        assert.ok(launches.every(response => response.status === 200));
        const first = await (await login('operator')).json();
        const second = await (await login('operator')).json();
        assert.ok(jwt.decode(second.token).exp > jwt.decode(second.token).iat);
        assert.equal((await request('/me', first.token)).status, 200);
        assert.equal((await request('/logout', second.token, { method: 'POST' })).status, 200);
        assert.equal((await request('/logout', token, { method: 'POST' })).status, 200);
        assert.equal((await request('/me', token)).status, 200);
        assert.equal((await (await login('sentra-hub')).json()).token, token);
    });

    await t.test('token still authenticates after a server restart', async () => {
        await closeServer();
        await startServer();
        assert.equal((await request('/me', token)).status, 200);
    });

    await t.test('missing, incorrect, expired and query tokens are rejected', async () => {
        assert.equal((await request('/me')).status, 401);
        assert.equal((await request('/me', `${token}-incorrect`)).status, 401);
        assert.equal((await request(`/me?token=${token}`)).status, 401);
        const expired = jwt.sign({ id: 2 }, process.env.JWT_SECRET, { expiresIn: -1 });
        assert.equal((await request('/me', expired)).status, 401);
    });

    await t.test('integration inherits account permissions and stops when account is deleted', async () => {
        assert.equal((await request('/users', token)).status, 403);
        integrationUser.role = 'admin';
        assert.equal((await request('/users', token)).status, 200);
        integrationUser.role = 'viewer';
        users.delete(1);
        assert.equal((await request('/me', token)).status, 401);
        users.set(1, integrationUser);
    });
});

test('integration is optional, supports a custom account and token rotation', () => {
    const result = spawnSync(process.execPath, ['-e', `
        const assert = require('node:assert/strict');
        const jwt = require('jsonwebtoken');
        const auth = require('./server/auth');
        const user = { id: 1, username: 'sentra-hub', role: 'viewer' };
        assert.ok(jwt.decode(auth.generateToken(user)).exp);
    `], { cwd: require('node:path').join(__dirname, '..'), env: { ...process.env, SENTRA_HUB_TOKEN: '' } });
    assert.equal(result.status, 0, result.stderr.toString());

    const rotatedToken = 'rotated-sentra-token-for-auth-tests-only';
    const rotated = spawnSync(process.execPath, ['-e', `
        const assert = require('node:assert/strict');
        const auth = require('./server/auth');
        const db = require('./server/db');
        auth.configureJwtStrategy(async () => null);
        db.users.getByUsername = async username => ({ id: 3, username, role: 'viewer' });
        const req = { headers: { authorization: 'Bearer ' + process.env.SENTRA_HUB_TOKEN } };
        auth.requireAuth(req, {}, () => assert.equal(req.user.username, 'custom-integration'));
        assert.equal(auth.generateToken({ username: 'custom-integration' }), process.env.SENTRA_HUB_TOKEN);
        auth.requireAuth({ headers: { authorization: 'Bearer sentra-persistent-token-for-auth-tests-only' } }, {
            setHeader() {}, end() { assert.equal(this.statusCode, 401); }
        }, () => assert.fail('Old token must be rejected'));
    `], { cwd: require('node:path').join(__dirname, '..'), env: {
        ...process.env, SENTRA_HUB_TOKEN: rotatedToken, SENTRA_HUB_USERNAME: 'custom-integration'
    } });
    assert.equal(rotated.status, 0, rotated.stderr.toString());
});

test('short integration tokens fail startup', () => {
    const result = spawnSync(process.execPath, ['-e', "require('./server/auth')"], {
        cwd: require('node:path').join(__dirname, '..'), env: { ...process.env, SENTRA_HUB_TOKEN: 'short' }
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr.toString(), /must contain at least 32 characters/);
});
