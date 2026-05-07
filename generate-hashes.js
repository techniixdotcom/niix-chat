#!/usr/bin/env node
/**
 * generate-hashes.js — NiiX Chat integrity system (Phase 5)
 *
 * Generates SHA-256 hashes of all public files and optionally signs them
 * with an Ed25519 key using Node's built-in crypto module.
 *
 * Usage:
 *   node generate-hashes.js               # hash only, no signature
 *   node generate-hashes.js --sign        # hash + sign (requires .signing-key)
 *   node generate-hashes.js --gen-key     # generate a new Ed25519 signing keypair
 *
 * Output:
 *   hashes.txt       — human-readable hash list (upload to GitHub Pages)
 *   hashes.txt.sig   — hex Ed25519 signature (upload alongside hashes.txt)
 *   signing-key.pub  — your public key in hex (publish on GitHub)
 *
 * The .signing-key file (private key) stays LOCAL — never upload it.
 */

'use strict';
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const PUBLIC_DIR = path.join(__dirname, 'public');
const FILES = [
  'index.html',
  'app.js',
  'crypto.js',
  'guide.js',
  'vendor-sodium.js',
];

const SIGNING_KEY_FILE = path.join(__dirname, '.signing-key');
const PUB_KEY_FILE     = path.join(__dirname, 'signing-key.pub');
const HASHES_FILE      = path.join(__dirname, 'hashes.txt');
const SIG_FILE         = path.join(__dirname, 'hashes.txt.sig');

// ── helpers ──────────────────────────────────────────────────────────────────

function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function generateSigningKeypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
  });
  fs.writeFileSync(SIGNING_KEY_FILE, privateKey.toString('hex'), { mode: 0o600 });
  fs.writeFileSync(PUB_KEY_FILE,     publicKey.toString('hex'));
  console.log('✓ Generated signing keypair');
  console.log(`  private key → ${SIGNING_KEY_FILE}  (keep secret, never upload)`);
  console.log(`  public key  → ${PUB_KEY_FILE}  (publish on GitHub)`);
  console.log(`\n  Public key hex:\n  ${publicKey.toString('hex')}`);
}

function loadPrivateKey() {
  if (!fs.existsSync(SIGNING_KEY_FILE)) {
    console.error(`\n  ✗ Signing key not found at ${SIGNING_KEY_FILE}`);
    console.error('  Run: node generate-hashes.js --gen-key\n');
    process.exit(1);
  }
  const hex = fs.readFileSync(SIGNING_KEY_FILE, 'utf8').trim();
  return crypto.createPrivateKey({
    key: Buffer.from(hex, 'hex'),
    format: 'der',
    type: 'pkcs8',
  });
}

function signData(data, privateKey) {
  return crypto.sign(null, Buffer.from(data), privateKey).toString('hex');
}

// ── main ─────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.includes('--gen-key')) {
  generateSigningKeypair();
  process.exit(0);
}

const doSign = args.includes('--sign');
const ts = new Date().toISOString();

console.log(`\n  NiiX Chat — integrity hash generator`);
console.log(`  ${ts}\n`);

// Hash all files
const lines = [
  `# NiiX Chat — integrity hashes`,
  `# Generated: ${ts}`,
  `# Verify against /api/integrity on the live server`,
  ``,
];

let allOk = true;
for (const name of FILES) {
  const full = path.join(PUBLIC_DIR, name);
  if (!fs.existsSync(full)) {
    console.warn(`  ⚠  ${name} not found — skipping`);
    lines.push(`MISSING  ${name}`);
    allOk = false;
    continue;
  }
  const hash = sha256File(full);
  lines.push(`${hash}  ${name}`);
  console.log(`  ✓  ${hash.slice(0, 16)}…  ${name}`);
}

const content = lines.join('\n') + '\n';
fs.writeFileSync(HASHES_FILE, content);
console.log(`\n  → Wrote ${HASHES_FILE}`);

if (doSign) {
  const pk = loadPrivateKey();
  const sig = signData(content, pk);
  fs.writeFileSync(SIG_FILE, sig);
  console.log(`  → Wrote ${SIG_FILE}`);
  console.log(`\n  Upload both hashes.txt and hashes.txt.sig to your GitHub Pages repo.`);
  if (fs.existsSync(PUB_KEY_FILE)) {
    console.log(`  Publish ${PUB_KEY_FILE} so users can verify the signature.`);
  }
} else {
  console.log(`\n  Tip: run with --sign to also produce a cryptographic signature.`);
  console.log(`  First time? run --gen-key to create a signing keypair.\n`);
}
