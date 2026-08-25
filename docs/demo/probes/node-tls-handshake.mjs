// Probe: can Node terminate TLS with a post-quantum certificate at all?
//
// Node links its own OpenSSL rather than the system one, so the answer depends
// entirely on which OpenSSL that build carries. The interesting result is that
// "supports PQC" is not one boolean: a build can handle ML-DSA end to end and
// still refuse to load an SLH-DSA certificate before a single byte is sent.
//
// Usage: node node-tls-handshake.mjs <fixture-dir> [label]
// Exits 0 if the handshake completed and the chain verified, 1 otherwise.

import tls from 'node:tls';
import fs from 'node:fs';
import path from 'node:path';

const dir = process.argv[2];
const label = process.argv[3] ?? dir;
if (!dir) {
  console.error('usage: node node-tls-handshake.mjs <fixture-dir> [label]');
  process.exit(2);
}

const read = (name) => fs.readFileSync(path.join(dir, name));
console.log(`  node                ${process.version}, OpenSSL ${process.versions.openssl}`);

const finish = (ok, detail) => {
  console.log(`  RESULT              ${ok ? 'PASS' : 'FAIL'} — ${detail}`);
  process.exit(ok ? 0 : 1);
};

let server;
try {
  // The failure for an unsupported certificate type happens here, building the
  // secure context — before listen(), before any client exists.
  server = tls.createServer({
    key: read('INSECURE-TEST-leaf.key.pem'),
    cert: read('INSECURE-TEST-fullchain.pem'),
  });
} catch (err) {
  finish(false, `${label} rejected at createSecureContext: ${err.code || err.message}`);
}

server.on('secureConnection', (socket) => socket.end('ok'));
server.on('tlsClientError', (err) => finish(false, `handshake refused: ${err.code || err.message}`));

server.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  const socket = tls.connect(
    {
      port,
      host: '127.0.0.1',
      servername: 'localhost',
      // Verify against the fixture set's own root, never the system store.
      ca: [read('INSECURE-TEST-root.cert.pem')],
    },
    () => {
      const peer = socket.getPeerCertificate();
      console.log(`  leaf certificate    ${peer.raw.length.toLocaleString()} B DER`);
      console.log(`  cipher              ${socket.getCipher().name}`);
      const ok = socket.authorized;
      socket.end();
      server.close(() =>
        finish(ok, ok ? `${label} handshake completed and verified` : `unauthorized: ${socket.authorizationError}`),
      );
    },
  );
  socket.on('error', (err) => {
    server.close(() => finish(false, `client: ${err.code || err.message}`));
  });
});
