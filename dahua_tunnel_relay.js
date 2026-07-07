#!/usr/bin/env node
/**
 * Dahua P2P Tunnel Relay Server v2.0
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

// ── Build P2P...
