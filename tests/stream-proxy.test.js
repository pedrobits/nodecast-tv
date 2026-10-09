const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');

async function listen(server) {
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    return `http://127.0.0.1:${server.address().port}`;
}

test('stream proxy forwards media without waiting for the source to finish', async (t) => {
    let liveClosed;
    const closed = new Promise(resolve => { liveClosed = resolve; });
    const upstream = http.createServer((req, res) => {
        if (req.url === '/live') {
            res.writeHead(200, { 'Content-Type': 'video/mp2t' });
            res.write('first-live-packet');
            // Deliberately leave the live response open.
            res.on('close', liveClosed);
        } else if (req.url === '/range') {
            assert.equal(req.headers.range, 'bytes=2-5');
            res.writeHead(206, {
                'Content-Type': 'video/mp4', 'Content-Length': '4',
                'Content-Range': 'bytes 2-5/10', 'Accept-Ranges': 'bytes'
            });
            res.end('2345');
        } else if (req.url === '/manifest') {
            res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
            res.write('#EX');
            setImmediate(() => res.end('TM3U\n#EXT-X-KEY:METHOD=AES-128,URI="key"\n#EXTINF:2,\nsegment.ts\n'));
        } else if (req.url === '/key') {
            res.end(Buffer.from([0, 1, 2, 3]));
        } else if (req.url === '/vod') {
            res.writeHead(200, { 'Content-Type': 'video/mp4', 'Content-Length': '16' });
            res.write('first-vod');
            setTimeout(() => res.end('-packet'), 100);
        }
    });
    const app = express();
    app.use('/api/proxy', require('../server/routes/proxy'));
    const proxy = http.createServer(app);
    t.after(async () => {
        upstream.closeAllConnections();
        proxy.closeAllConnections();
        await Promise.all([upstream, proxy].map(server => new Promise(resolve => server.close(resolve))));
    });
    const origin = await listen(upstream);
    const base = await listen(proxy);
    const url = path => `${base}/api/proxy/stream?url=${encodeURIComponent(origin + path)}`;

    await t.test('live bytes arrive before EOF and disconnect cancels upstream', async () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 2000);
        try {
            const response = await fetch(url('/live'), { signal: controller.signal });
            assert.equal(response.status, 200);
            assert.equal(response.headers.get('content-length'), null);
            const reader = response.body.getReader();
            const chunk = await reader.read();
            assert.equal(Buffer.from(chunk.value).toString(), 'first-live-packet');
            controller.abort();
            await Promise.race([closed, new Promise((_, reject) => {
                const timeout = setTimeout(() => reject(new Error('Upstream connection stayed open')), 1000);
                closed.then(() => clearTimeout(timeout));
            })]);
        } finally {
            clearTimeout(timer);
            controller.abort();
        }
    });

    await t.test('VOD keeps its length and contents', async () => {
        const response = await fetch(url('/vod'));
        assert.equal(response.headers.get('content-length'), '16');
        assert.equal(await response.text(), 'first-vod-packet');
    });

    await t.test('seeking preserves Range, 206 and Content-Range', async () => {
        const response = await fetch(url('/range'), { headers: { Range: 'bytes=2-5' } });
        assert.equal(response.status, 206);
        assert.equal(response.headers.get('content-range'), 'bytes 2-5/10');
        assert.equal(await response.text(), '2345');
    });

    await t.test('split HLS signature still rewrites segment and key URLs', async () => {
        const response = await fetch(url('/manifest'));
        assert.equal(response.headers.get('content-type'), 'application/vnd.apple.mpegurl; charset=utf-8');
        const manifest = await response.text();
        assert.ok(manifest.includes(url('/segment.ts')));
        assert.ok(manifest.includes(`URI="${url('/key')}"`));
        assert.equal(Number(response.headers.get('content-length')), Buffer.byteLength(manifest));
    });

    await t.test('small binary keys remain intact', async () => {
        const response = await fetch(url('/key'));
        assert.deepEqual(Buffer.from(await response.arrayBuffer()), Buffer.from([0, 1, 2, 3]));
    });
});
