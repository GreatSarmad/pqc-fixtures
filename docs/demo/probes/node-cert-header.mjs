// Probe: a PQC certificate forwarded in an HTTP header by a TLS-terminating
// proxy overflows Node's default header buffer.
//
// The pattern is everywhere in mTLS deployments: the proxy terminates TLS and
// passes the verified client certificate to the app in a header —
// nginx's `ssl_client_escaped_cert`, AWS ALB's `x-amzn-mtls-clientcert`,
// Envoy's `x-forwarded-client-cert`. The app never sees the handshake, only
// the header.
//
// Node's default `--max-http-header-size` is 16,384 bytes for *all* headers
// combined. A URL-escaped RSA-2048 certificate is about 2 KB and fits with
// room to spare. A URL-escaped ML-DSA or SLH-DSA certificate does not.
//
// Usage: node node-cert-header.mjs <cert.pem> [label]
// Exits 0 if the request completed, 1 if the certificate broke the request.

import http from 'node:http';
import fs from 'node:fs';

const certPath = process.argv[2];
const label = process.argv[3] ?? certPath;
if (!certPath) {
  console.error('usage: node node-cert-header.mjs <cert.pem> [label]');
  process.exit(2);
}

const pem = fs.readFileSync(certPath, 'utf8');
const headerValue = encodeURIComponent(pem);

const limit = http.maxHeaderSize;
console.log(`  certificate         ${pem.length.toLocaleString()} B PEM`);
console.log(`  URL-escaped header  ${headerValue.length.toLocaleString()} B`);
console.log(`  node header limit   ${limit.toLocaleString()} B (http.maxHeaderSize, default)`);

const server = http.createServer((req, res) => {
  // Reached only if the header survived parsing.
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('ok');
});

let serverDiagnosis = null;
server.on('clientError', (err, socket) => {
  serverDiagnosis = err.code || err.message;
  socket.destroy();
});

const finish = (ok, detail) => {
  server.close(() => {
    if (ok) {
      console.log(`  RESULT              PASS — ${label} was delivered intact`);
      process.exit(0);
    }
    console.log(`  RESULT              FAIL — ${detail}`);
    process.exit(1);
  });
};

server.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  const req = http.request(
    { host: '127.0.0.1', port, path: '/', headers: { 'x-client-cert': headerValue } },
    (res) => {
      res.resume();
      res.on('end', () => finish(res.statusCode === 200, `server answered ${res.statusCode}`));
    },
  );
  req.on('error', (err) => {
    const client = err.code || err.message;
    // The interesting part is the server's own diagnosis: Node's HTTP parser
    // aborts the message rather than answering 431, so the client sees only a
    // reset connection and has no idea why.
    finish(false, `server ${serverDiagnosis ?? 'aborted'}, client saw ${client}`);
  });
  req.end();
});
