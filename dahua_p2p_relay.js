#!/usr/bin/env node
/**
 * Dahua P2P UDP Relay
 * ===================
 * HTTP server that relays P2P status queries to Dahua's UDP-based P2P cloud.
 * Deploy on any platform that supports UDP (Fly.io, Render, VPS, etc.).
 *
 * Deploy on Fly.io (free):
 *   1. npm init -y
 *   2. flyctl launch --no-deploy
 *   3. flyctl deploy
 *
 * Deploy on Render (free):
 *   1. Create new Web Service
 *   2. Connect this file
 *   3. Build: npm install
 *   4. Start: node dahua_p2p_relay.js
 *
 * Deploy on any VPS:
 *   node dahua_p2p_relay.js
 *
 * Usage:
 *   GET http://your-server:8080/5H0504CPAJ1234
 *   -> { "serial": "...", "online": true/false, "relay": "...", "error": null }
 */

const http = require('http');
const dgram = require('dgram');
const dns = require('dns');
const crypto = require('crypto');

const MAIN_SERVER = "www.easy4ipcloud.com";
const MAIN_PORT = 8800;
const USERNAME = "cba1b29e32cb17aa46b8ff9e73c7f40b";
const USERKEY = "996103384cdf19179e19243e959bbf8b";
const TIMEOUT_MS = 4000;
const PORT = process.env.PORT || 8080;

function buildRequest(path) {
  const nonce = Math.floor(Math.random() * 2147483647);
  const curdate = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const pwd = nonce + curdate + 'DHP2P:' + USERNAME + ':' + USERKEY;
  const digest = crypto.createHash('sha1').update(pwd).digest('base64');
  return (
    'DHGET ' + path + ' HTTP/1.1\r\n' +
    'CSeq: 1\r\n' +
    'Authorization: WSSE profile="UsernameToken"\r\n' +
    'X-WSSE: UsernameToken Username="' + USERNAME + '", ' +
    'PasswordDigest="' + digest + '", Nonce="' + nonce + '", Created="' + curdate + '"\r\n' +
    '\r\n'
  );
}

function resolveHostname(hostname) {
  return new Promise((resolve, reject) => {
    dns.resolve4(hostname, (err, addresses) => {
      if (err) reject(err);
      else resolve(addresses[0]);
    });
  });
}

function sendUDP(ip, port, message) {
  return new Promise((resolve) => {
    const client = dgram.createSocket('udp4');
    let resolved = false;
    const msg = Buffer.from(message, 'utf8');

    client.on('message', (data) => {
      if (resolved) return;
      resolved = true;
      client.close();
      resolve(data.toString('utf8'));
    });

    client.on('error', () => {
      if (resolved) return;
      resolved = true;
      try { client.close(); } catch (e) {}
      resolve(null);
    });

    setTimeout(() => {
      if (resolved) return;
      resolved = true;
      try { client.close(); } catch (e) {}
      resolve(null);
    }, TIMEOUT_MS);

    client.send(msg, port, ip, (err) => {
      if (err && !resolved) {
        resolved = true;
        try { client.close(); } catch (e) {}
        resolve(null);
      }
    });
  });
}

async function checkP2P(serial) {
  const mainIp = await resolveHostname(MAIN_SERVER);
  const req1 = buildRequest('/online/p2psrv/' + serial);
  const res1 = await sendUDP(mainIp, MAIN_PORT, req1);

  if (!res1) return { serial, online: false, error: 'Main server timeout' };

  let relayAddr = null;
  const dsMatch = res1.match(/<DS>([^<]+)<\/DS>/);
  const usMatch = res1.match(/<US>([^<]+)<\/US>/);
  if (dsMatch) relayAddr = dsMatch[1].trim();
  else if (usMatch) relayAddr = usMatch[1].trim();

  if (!relayAddr) return { serial, online: false, error: 'No relay server in response' };

  const parts = relayAddr.split(':');
  const relayIp = parts[0];
  const relayPort = parts.length > 1 ? parseInt(parts[1]) : MAIN_PORT;

  const req2 = buildRequest('/probe/device/' + serial);
  const probeRes = await sendUDP(relayIp, relayPort, req2);

  if (!probeRes) return { serial, online: false, relay: relayAddr, error: 'Device offline (probe timeout)' };

  const isOnline = probeRes.includes('200 OK');
  return {
    serial,
    online: isOnline,
    relay: relayAddr,
    error: isOnline ? null : 'Probe returned non-200'
  };
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  const serial = req.url.replace(/^\//, '').split('?')[0];

  if (!serial || serial.length < 10) {
    res.writeHead(400);
    return res.end(JSON.stringify({ error: 'Serial number must be at least 10 characters' }));
  }

  try {
    const result = await checkP2P(serial);
    res.writeHead(200);
    res.end(JSON.stringify(result));
  } catch (err) {
    res.writeHead(500);
    res.end(JSON.stringify({ error: err.message }));
  }
});

server.listen(PORT, () => {
  console.log('Dahua P2P Relay running on port ' + PORT);
  console.log('Usage: GET http://localhost:' + PORT + '/<serial>');
});
