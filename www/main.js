const configApi = '/api/config';
const statusApi = '/api/status';
const fetchTimeout = 5000;

function convertUptime(seconds) {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);

    let ret = '';
    if (d > 1) {
        ret = `${d} days, `;
    } else if (d === 1) {
        ret = `${d} day, `;
    }

    function pad(x) {
        return x.toString().padStart(2, '0');
    }

    ret += `${pad(h)}:${pad(m)}:${pad(s)}`;

    return ret;
}

function convertHyphens(str) {
    const shy = '\u00ad';
    return str.replaceAll('_', `_${shy}`);
}

function convertBytes(amount) {
    if (!Number.isFinite(amount) || amount < 0) {
        return '';
    }
    if (amount < 1024) {
        return amount.toString() + ' B';
    }

    const units = ['KiB', 'MiB', 'GiB', 'TiB'];
    let v = amount / 1024;
    let i = 0;

    while (v >= 1024 && i < units.length - 1) {
        v /= 1024;
        i++;
    }

    return v.toFixed(1) + ' ' + units[i];
}

function convertRtt(us) {
    if (!Number.isFinite(us) || us == 0) {
        return '0';
    }
    const ms = us / 1000;
    return ms.toFixed(1);
}

function showStatus(json) {
    json.sys.uptime = convertUptime(json.sys.uptime);
    json.tun.cipher_suite = convertHyphens(json.tun.cipher_suite);
    json.tun.rtt = convertRtt(json.tun.rtt);

    json.tun.sent_orig_bytes = convertBytes(json.tun.sent_orig_bytes);
    json.tun.sent_bytes = convertBytes(json.tun.sent_bytes);
    json.tun.rcvd_orig_bytes = convertBytes(json.tun.rcvd_orig_bytes);
    json.tun.rcvd_bytes = convertBytes(json.tun.rcvd_bytes);

    const table = document.getElementById('status-table');
    const tbody = document.createElement('tbody');
    for (const [keyG, valG] of Object.entries(json)) {
        const rowG = tbody.insertRow();
        rowG.insertCell(0).textContent = keyG;
        rowG.insertCell(1);
        rowG.className = 'status-group';
        for (const [key, val] of Object.entries(valG)) {
            const row = tbody.insertRow();
            row.insertCell(0).textContent = key;
            row.insertCell(1).textContent = val;
            row.className = 'status-entry';
        }
        if (Object.keys(valG).length % 2 === 1) {
            const row = tbody.insertRow();
            row.className = 'status-entry';
            row.style.display = 'none';
        }
    }

    table.replaceChild(tbody, table.tBodies[0]);
}

function showFeedback(message) {
    const feedback = document.getElementById('feedback-text');
    feedback.innerHTML = message;
}

function showConfig(text) {
    const textarea = document.getElementById('config-textarea');
    textarea.value = text;
    textarea.disabled = false;
}

async function submitConfig(event) {
    event.preventDefault();
    try {
        const text = document.getElementById('config-textarea').value;
        for (let i = 0; i < text.length; ++i) {
            if (text.charCodeAt(i) > 0x7f) {
                throw new Error(`A non-ASCII char at index ${i}`);
            }
        }
        showFeedback('Posting...');
        const postResp = await fetch(configApi, {
            method: 'POST',
            body: text,
            signal: AbortSignal.timeout(fetchTimeout),
        });
        if (!postResp.ok) {
            throw new Error(`HTTP ${postResp.status} POST ${configApi}`);
        }
        const message = await postResp.json();
        showFeedback(message.report);
    } catch (error) {
        showFeedback(error.message);
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    try {
        const statusResp = await fetch(statusApi, {
            signal: AbortSignal.timeout(fetchTimeout),
        });
        if (!statusResp.ok) {
            throw new Error(`HTTP ${statusResp.status} GET ${statusApi}`);
        }
        const statusJson = await statusResp.json();
        showStatus(statusJson);

        const configResp = await fetch(configApi, {
            signal: AbortSignal.timeout(fetchTimeout),
        });
        if (!configResp.ok) {
            throw new Error(`HTTP ${configResp.status} GET ${configApi}`);
        }
        const configText = await configResp.text();
        showConfig(configText);

        const button = document.getElementById('submit-button');
        button.addEventListener('click', submitConfig);
        button.disabled = false;
    } catch (error) {
        showFeedback(error.message);
    }
});
