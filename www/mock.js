import fs from 'node:fs';

const mock_status = {
    sys: {
        uptime: 2485,
        reboot_count: 43,
        lan_connected: 0,
    },
    heap: {
        free: 85408,
        allocated: 45680,
        max_allocated: 63952,
    },
    lan: {
        num_connected: 1,
    },
    wan: {
        status: 'connected',
        address: '192.168.3.44/24',
        gateway: '192.168.3.1',
    },
    tun: {
        rcvd_orig_bytes: 354654,
        rcvd_bytes: 645585,
        rcvd_packets: 5816,
        sent_orig_bytes: 599320,
        sent_bytes: 851637,
        sent_packets: 11427,
        allocs_failed: 0,
        downs: 0,
        version: 'DTLSv1.3',
        curve_name: 'X25519',
        cipher_suite: 'TLS_CHACHA20_POLY1305_SHA256',
    },
};

const mock_config = fs.readFileSync('../default.toml', 'ascii');

function mock(req, res, next) {
    if (req.url === '/api/status') {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(mock_status));
    } else if (req.url === '/api/config') {
        if (req.method === 'GET') {
            res.setHeader('Content-Type', 'application/toml');
            res.end(mock_config);
        } else if (req.method === 'POST') {
            res.statusCode = 200;
            res.end('Saved');
        } else {
            next();
        }
    } else {
        next();
    }
}

export function mockApiPlugin() {
    return {
        name: 'mock-api',
        configureServer(server) {
            server.middlewares.use(mock);
        },
    };
}
