// PHProtect rules: which wallet requests, typed-data signatures and clipboard
// writes deserve a human decision. Pure functions, unit-tested in Node.
//
// Loaded in the extension's isolated world, so the page cannot patch these.
// This file decides *severity and shape*; background.js rebuilds all wording.
(() => {
  "use strict";

  const HUGE = 1n << 128n; // effectively unlimited for any real token

  const SEL = {
    approve: "0x095ea7b3",
    setApprovalForAll: "0xa22cb465",
    increaseAllowance: "0x39509351",
    permit2Approve: "0x87517c45",
    permit: "0xd505accf",
    transferFrom: "0x23b872dd",
    safeTransferFrom: "0x42842e0e",
    safeTransferFromData: "0xb88d4fde",
  };
  const MULTICALL = new Set(["0xac9650d8", "0x5ae401dc", "0x1f0464d1"]);

  const addr = (a) => (typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a) ? a : "");
  const safeAddr = (a) => (addr(a) ? `${a.slice(0, 6)}\u2026${a.slice(-4)}` : "an unknown address");
  const safeName = (s) =>
    typeof s === "string" && /^[\w .\-+:]{1,40}$/.test(s) ? s : "an unknown contract";
  const word = (data, i) => data.slice(10 + i * 64, 10 + (i + 1) * 64);
  const wordAddr = (w) => "0x" + (w || "").slice(24).toLowerCase();
  const big = (w) => {
    try {
      return BigInt("0x" + (w || "0"));
    } catch {
      return 0n;
    }
  };
  const decimal = (v) => (v >= HUGE ? "UNLIMITED" : v.toString());

  const decodeHexText = (hex) => {
    if (typeof hex !== "string" || !/^0x[0-9a-f]{2,}$/i.test(hex)) return "";
    const bytes = new Uint8Array((hex.length - 2) / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 + i * 2, 4 + i * 2), 16);
    try {
      return new TextDecoder().decode(bytes).slice(0, 2000);
    } catch {
      return "";
    }
  };

  // chainId may be hex, decimal or a number; return a short display value only.
  const chainId = (v) => {
    try {
      let n;
      if (typeof v === "number") n = v;
      else if (typeof v === "string" && /^0x[0-9a-f]+$/i.test(v)) n = Number.parseInt(v, 16);
      else if (typeof v === "string" && /^\d+$/.test(v)) n = Number(v);
      else return "";
      return Number.isSafeInteger(n) && n > 0 ? String(n) : "";
    } catch {
      return "";
    }
  };

  const CHAINS = {
    1: "Ethereum",
    10: "Optimism",
    56: "BNB Chain",
    100: "Gnosis",
    137: "Polygon",
    250: "Fantom",
    324: "zkSync",
    8453: "Base",
    42161: "Arbitrum One",
    43114: "Avalanche",
    59144: "Linea",
    534352: "Scroll",
    7777777: "Zora",
    81457: "Blast",
    11155111: "Sepolia",
  };

  // Unix seconds, ms or ISO string -> unix seconds (bounded).
  const deadlineOf = (v) => {
    if (v === undefined || v === null) return "";
    let n = 0;
    if (typeof v === "number") n = v;
    else if (typeof v === "string" && /^\d+$/.test(v)) n = Number(v);
    else if (typeof v === "string" && v.length <= 40) n = Math.floor(Date.parse(v) / 1000) || 0;
    if (!n) return "";
    if (n > 1e12) n = Math.floor(n / 1000);
    return n > 1e9 && n < 4e9 ? String(n) : "";
  };

  const dataOf = (tx) => {
    if (!tx || typeof tx !== "object") return "";
    const d = [tx.data, tx.input].find((x) => typeof x === "string" && x.length >= 10);
    return d ? d.toLowerCase() : "";
  };

  // ---- transaction calls ------------------------------------------------------------
  function classifyCall(tx) {
    if (!tx || typeof tx !== "object") return null;

    if (Array.isArray(tx.authorizationList) && tx.authorizationList.length) {
      const who = addr(tx.authorizationList[0] && tx.authorizationList[0].address);
      return {
        f: { who: who || tx.to },
        level: "high",
        code: "eip7702",
        title: "Account delegation (EIP-7702)",
        reasons: [
          `This lets ${safeAddr(who || tx.to)} act as your account${tx.authorizationList.length > 1 ? " (and more)" : ""}.`,
          "A malicious delegation can move everything you own without another prompt.",
        ],
      };
    }

    const data = dataOf(tx);
    const sel = data.slice(0, 10);

    if (MULTICALL.has(sel)) {
      const inner = scanCalls(data, tx.to);
      const worst = inner.find((x) => x.level === "high") || inner[0];
      if (worst) {
        return {
          ...worst,
          code: worst.code,
          level: worst.level,
          title: `Batched call: ${worst.title.toLowerCase()}`,
          reasons: [
            ...worst.reasons,
            `It is one part of a batch of ${inner.length || "several"} calls.`,
          ],
          f: { ...worst.f, count: inner.length || 0, selector: sel },
        };
      }
      return {
        level: "medium",
        code: "multicall",
        title: "Batched contract call",
        reasons: [
          "Several contract calls are sent at once, so one confirmation can hide another action.",
        ],
        f: { selector: sel, count: 0 },
      };
    }

    if (sel === SEL.approve) {
      const spender = wordAddr(word(data, 0));
      const v = big(word(data, 1));
      return {
        f: {
          who: spender,
          token: tx.to,
          amount: decimal(v),
          unlimited: v >= HUGE,
          selector: sel,
        },
        level: v >= HUGE ? "high" : "medium",
        code: v >= HUGE ? "approve-unlimited" : "approve",
        title: v >= HUGE ? "Unlimited token approval" : "Token approval",
        reasons: [
          `Lets ${safeAddr(spender)} spend ${v >= HUGE ? "UNLIMITED amounts" : "a set amount"} of token ${safeAddr(tx.to)} from your wallet.`,
          "Drainers use approvals to empty wallets later, without asking again.",
        ],
      };
    }

    if (sel === SEL.increaseAllowance) {
      const spender = wordAddr(word(data, 0));
      const v = big(word(data, 1));
      return {
        f: {
          who: spender,
          token: tx.to,
          amount: decimal(v),
          unlimited: v >= HUGE,
          selector: sel,
        },
        level: v >= HUGE ? "high" : "medium",
        code: "allowance",
        title: "Token allowance increase",
        reasons: [
          `Lets ${safeAddr(spender)} spend ${v >= HUGE ? "UNLIMITED amounts more" : "more"} of token ${safeAddr(tx.to)}.`,
        ],
      };
    }

    if (sel === SEL.setApprovalForAll && big(word(data, 1)) !== 0n) {
      const operator = wordAddr(word(data, 0));
      return {
        f: { who: operator, token: tx.to, selector: sel },
        level: "high",
        code: "approval-for-all",
        title: "Approval for ALL your NFTs",
        reasons: [
          `Gives ${safeAddr(operator)} control of every NFT you hold in collection ${safeAddr(tx.to)}.`,
          "This is the number one trick NFT drainers use.",
        ],
      };
    }

    if (sel === SEL.permit2Approve) {
      const token = wordAddr(word(data, 0));
      const spender = wordAddr(word(data, 1));
      const v = big(word(data, 2));
      return {
        f: {
          who: spender,
          token,
          amount: decimal(v),
          unlimited: v >= HUGE,
          selector: sel,
        },
        level: "high",
        code: "permit2-approve",
        title: "Permit2 approval",
        reasons: [
          `Lets ${safeAddr(spender)} move ${v >= HUGE ? "UNLIMITED amounts" : "a set amount"} of token ${safeAddr(token)} via Permit2.`,
        ],
      };
    }

    if (sel === SEL.permit) {
      const spender = wordAddr(word(data, 1));
      const v = big(word(data, 2));
      return {
        f: {
          who: spender,
          token: tx.to,
          amount: decimal(v),
          unlimited: v >= HUGE,
          selector: sel,
        },
        level: "high",
        code: "permit-onchain",
        title: "On-chain token permit",
        reasons: [
          `This approves ${safeAddr(spender)} to spend ${v >= HUGE ? "UNLIMITED amounts" : "a set amount"} of token ${safeAddr(tx.to)} in the same transaction.`,
        ],
      };
    }

    if (sel === SEL.transferFrom) {
      return {
        f: {
          token: tx.to,
          from: wordAddr(word(data, 0)),
          to: wordAddr(word(data, 1)),
          amount: decimal(big(word(data, 2))),
          selector: sel,
        },
        level: "medium",
        code: "transfer-from",
        title: "Token transfer pulls from your wallet",
        reasons: [
          `Moves token ${safeAddr(tx.to)} from ${safeAddr(wordAddr(word(data, 0)))} to ${safeAddr(wordAddr(word(data, 1)))}.`,
          "The contract needs an allowance to do this.",
        ],
      };
    }

    if (sel === SEL.safeTransferFrom || sel === SEL.safeTransferFromData) {
      return {
        f: {
          token: tx.to,
          from: wordAddr(word(data, 0)),
          to: wordAddr(word(data, 1)),
          selector: sel,
        },
        level: "medium",
        code: "nft-transfer",
        title: "NFT transfer",
        reasons: [
          `Moves an NFT from ${safeAddr(wordAddr(word(data, 0)))} to ${safeAddr(wordAddr(word(data, 1)))}.`,
        ],
      };
    }

    // A payable call to a contract: no selector, but ETH leaves the wallet.
    if (!data && tx.value && /^0x[1-9a-f][0-9a-f]*$/i.test(String(tx.value))) {
      const v = big(String(tx.value).slice(2).padStart(64, "0"));
      return {
        f: { who: tx.to, amount: decimal(v), token: "" },
        level: "medium",
        code: "payable-call",
        title: "Sends ETH to a contract",
        reasons: [
          "The call sends value but carries no readable instruction. Make sure you know what the contract does with it.",
        ],
      };
    }

    if (!addr(tx.to)) {
      return {
        level: "medium",
        code: "create-contract",
        title: "Deploys a new contract",
        reasons: ["This transaction creates a contract instead of calling one."],
        f: {},
      };
    }
    return null;
  }

  // Find approval-shaped calls inside multicall calldata. Best effort: offsets
  // are 32-byte aligned, so parse words after each selector occurrence.
  function scanCalls(data, token) {
    const out = [];
    for (const sel of Object.values(SEL)) {
      let at = data.indexOf(sel, 2);
      while (at !== -1 && out.length < 8) {
        const tail = data.slice(at);
        const inner = {};
        if (sel === SEL.approve) {
          const v = big(word(tail, 1));
          inner.level = v >= HUGE ? "high" : "medium";
          inner.code = v >= HUGE ? "approve-unlimited" : "approve";
          inner.title = v >= HUGE ? "Unlimited token approval" : "Token approval";
          inner.f = {
            who: wordAddr(word(tail, 0)),
            token: addr(token),
            amount: decimal(v),
            unlimited: v >= HUGE,
            selector: sel,
          };
          inner.reasons = [
            `An approval hidden in the batch lets ${safeAddr(wordAddr(word(tail, 0)))} spend ${v >= HUGE ? "UNLIMITED amounts" : "a set amount"}.`,
          ];
        } else if (sel === SEL.setApprovalForAll && big(word(tail, 1)) !== 0n) {
          inner.level = "high";
          inner.code = "approval-for-all";
          inner.title = "Approval for ALL NFTs";
          inner.f = { who: wordAddr(word(tail, 0)), selector: sel };
          inner.reasons = [
            `Gives ${safeAddr(wordAddr(word(tail, 0)))} control of every NFT in a collection.`,
          ];
        } else if (sel === SEL.permit2Approve) {
          inner.level = "high";
          inner.code = "permit2-approve";
          inner.title = "Permit2 approval";
          inner.f = {
            who: wordAddr(word(tail, 1)),
            token: wordAddr(word(tail, 0)),
            selector: sel,
          };
          inner.reasons = [`A Permit2 approval is bundled in this batch.`];
        } else {
          out.push({
            level: "medium",
            code: "batched-call",
            title: "Batched contract call",
            reasons: ["A contract call is bundled in this batch."],
            f: { selector: sel },
          });
          at = data.indexOf(sel, at + 8);
          continue;
        }
        if (inner.code) out.push(inner);
        at = data.indexOf(sel, at + 8);
      }
    }
    return out;
  }

  // ---- typed-data signatures --------------------------------------------------------
  function classifyTypedData(raw) {
    let td = raw;
    if (typeof raw === "string") {
      try {
        td = JSON.parse(raw);
      } catch {
        return null;
      }
    }
    if (!td || typeof td !== "object") return null;

    const pt = String(td.primaryType || "");
    const msg = td.message && typeof td.message === "object" ? td.message : {};
    const domain = td.domain && typeof td.domain === "object" ? td.domain : {};
    const domainName = typeof domain.name === "string" ? domain.name : "";
    const name = safeName(domainName);
    const chain = chainId(domain.chainId);
    const verifying = addr(domain.verifyingContract);
    const deadline = deadlineOf(
      msg.deadline ?? msg.expiration ?? msg.expiry ?? msg.endTime ?? msg.sigDeadline
    );
    const now = Math.floor(Date.now() / 1000);
    const expired = deadline && Number(deadline) < now;

    const base = (o) => ({
      ...o,
      f: { ...o.f, domain: domainName, chain, deadline, expired },
    });

    // Permit2 shapes nest their details.
    if (/permit/i.test(pt)) {
      const d = Array.isArray(msg.details) ? msg.details[0] : msg.details;
      const details = d && typeof d === "object" ? d : {};
      const spender = addr(msg.spender) || addr(details.spender);
      const token = addr(msg.token) || addr(details.token) || verifying;
      const amountRaw = msg.value ?? msg.amount ?? details.amount;
      let amount = "";
      try {
        amount = amountRaw === undefined ? "" : decimal(BigInt(String(amountRaw)));
      } catch {
        amount = "";
      }
      const unlimited = amount === "UNLIMITED";
      // Permit2 uses PermitSingle / PermitBatch / PermitTransferFrom and nests
      // its details, so it needs sharper wording than a plain EIP-2612 permit.
      const permit2 = /permit2|permit(?:batch|single|transfer)/i.test(pt);
      return base({
        level: "high",
        code: permit2 ? "permit2-signature" : "permit",
        title: permit2 ? "Permit2 gasless approval" : "Permit signature (gasless approval)",
        reasons: [
          `Signing lets ${safeAddr(spender)} move ${unlimited ? "UNLIMITED amounts" : "tokens"} of ${safeAddr(token)} without another transaction.`,
          "It costs no gas and looks harmless, which is exactly why drainers use it.",
        ],
        f: { who: spender, token, amount, unlimited },
      });
    }

    if (
      pt === "OrderComponents" ||
      /seaport|blur|opensea/i.test(`${pt} ${domainName}`) ||
      (pt === "Root" && /blur/i.test(domainName))
    ) {
      const offer = Array.isArray(msg.offer) ? msg.offer.length : 0;
      const consideration = Array.isArray(msg.consideration) ? msg.consideration.length : 0;
      return base({
        level: "high",
        code: "market-order",
        title: "Marketplace order signature",
        reasons: [
          `This signs a ${name} order (${offer} offered, ${consideration} requested). A malicious one can sell your assets for almost nothing.`,
          "Only sign if you are deliberately listing something on the real marketplace.",
        ],
        f: { domain: domainName, count: offer + consideration },
      });
    }

    if (/delegat|authoriz/i.test(pt)) {
      const delegate = addr(msg.delegate) || addr(msg.delegatee);
      return base({
        level: "high",
        code: "delegation",
        title: "Delegation / authorization signature",
        reasons: [
          `Signing hands control of your account or assets${delegate ? ` to ${safeAddr(delegate)}` : ""} until you revoke it.`,
        ],
        f: { who: delegate },
      });
    }

    return null;
  }

  // ---- readable personal_sign -------------------------------------------------------
  // personal_sign params are [message, address], but wallets differ in order.
  // Ignore a bare 20-byte address and judge the message itself.
  function classifyPersonalSign(params) {
    const p = Array.isArray(params) ? params : [params];
    const candidates = p.filter((c) => typeof c === "string" && c);
    const message = candidates.find((c) => !/^0x[0-9a-f]{40}$/i.test(c));
    if (!message) return null;
    // A bare 32-byte hash carries no readable meaning at all.
    if (/^0x[0-9a-f]{64}$/i.test(message)) {
      return {
        level: "high",
        code: "blind-hash",
        title: "Blind hash signature",
        reasons: ["You are asked to sign a 32-byte hash, not readable text."],
        f: {},
      };
    }
    const text = /^0x/i.test(message) ? decodeHexText(message) : message;
    if (!text) return null;
    if (/sign in with ethereum|wants you to sign in with your ethereum account/i.test(text))
      return null;
    if (
      /(approve|allowance|permit|spender|unlimited|setapprovalforall|seaport|opensea)/i.test(text)
    ) {
      return {
        level: "medium",
        code: "signature-text",
        title: "Signature with approval wording",
        reasons: [
          "The page's own wording says this signature grants spending rights. Read the wallet carefully, it may still be a drainer.",
        ],
        f: {},
      };
    }
    return null;
  }

  const WALLET_ACTION =
    /^(eth_sendTransaction|eth_signTransaction|eth_sign|personal_sign|eth_signTypedData(_v3|_v4)?|wallet_sendCalls|wallet_grantPermissions|wallet_addEthereumChain|wallet_switchEthereumChain|wallet_watchAsset)$/;

  function classify(method, params, ctx) {
    const risky = !!(ctx && ctx.risky);
    const p = Array.isArray(params) ? params : [params];
    let r = null;

    switch (method) {
      case "eth_sendTransaction":
      case "eth_signTransaction":
        r = classifyCall(p[0]);
        break;
      case "wallet_sendCalls": {
        const calls = (p[0] && Array.isArray(p[0].calls) && p[0].calls) || [];
        if (calls.length > 1) {
          let worst = null;
          for (const c of calls) {
            const x = classifyCall(c);
            if (x && (!worst || x.level === "high")) worst = x;
          }
          if (worst)
            r = {
              ...worst,
              title: `Batch of ${calls.length}: ${worst.title.toLowerCase()}`,
              f: { ...worst.f, count: calls.length },
            };
          else
            r = {
              level: "medium",
              code: "batched-call",
              title: "Batched wallet calls",
              reasons: ["Several calls are confirmed at once."],
              f: { count: calls.length },
            };
        } else if (calls.length === 1) {
          r = classifyCall(calls[0]);
        }
        break;
      }
      case "eth_signTypedData":
      case "eth_signTypedData_v3":
      case "eth_signTypedData_v4": {
        const data =
          p.find((x) => x && typeof x === "object") ||
          p.find((x) => typeof x === "string" && x.trim().startsWith("{")) ||
          p[1] ||
          p[0];
        r = classifyTypedData(data);
        break;
      }
      case "eth_sign":
        r = {
          level: "high",
          code: "eth-sign",
          title: "Blind signature (eth_sign)",
          reasons: [
            "eth_sign signs a raw hash you cannot read. It can authorize almost anything, including draining the wallet.",
          ],
          f: {},
        };
        break;
      case "personal_sign":
        r = classifyPersonalSign(p);
        break;
      case "wallet_addEthereumChain": {
        const c = p[0] || {};
        const id = chainId(c.chainId) || chainId(typeof c.chainId === "string" ? c.chainId : "");
        const rpc = Array.isArray(c.rpcUrls) ? c.rpcUrls[0] : "";
        return {
          level: "high",
          code: "chain-add",
          title: "Adds a custom network",
          reasons: [
            "A page can add a network with its own RPC server. That server chooses which chain state and balances you see, and can quietly redirect transactions.",
            "Only continue if you recognise the network name.",
          ],
          f: {
            name: typeof c.chainName === "string" ? c.chainName : "",
            chain: id,
            origin: typeof rpc === "string" ? rpc.replace(/\/+$/, "") : "",
          },
        };
      }
      case "wallet_switchEthereumChain": {
        const id = chainId(p[0] && p[0].chainId);
        return {
          level: "medium",
          code: "chain-switch",
          title: `Switch network to ${CHAINS[id] || "an unknown chain"}`,
          reasons: [
            "The site wants your wallet pointed at a different chain. Tokens and approvals live per chain.",
          ],
          f: { chain: id },
        };
      }
      case "wallet_watchAsset": {
        const a = p[0] || {};
        const o = a.options || a;
        return {
          level: "medium",
          code: "watch-asset",
          title: "Adds a token to your wallet",
          reasons: [
            "Anyone can create a token with any name; a fake one can be made to look valuable.",
          ],
          f: {
            name: typeof o.symbol === "string" ? o.symbol : "",
            token: addr(o.address),
          },
        };
      }
      case "wallet_grantPermissions": {
        const g = p[0] || {};
        return {
          level: "high",
          code: "grant-permissions",
          title: "Grants spending permissions (EIP-7715)",
          reasons: [
            "A permission grants another account ongoing rights over your tokens, often without a prompt next time.",
          ],
          f: {},
        };
      }
    }

    if (r && risky) r.risky = true;
    if (risky && WALLET_ACTION.test(method)) {
      const note = "This site advertises an unpatched PHP version and may be compromised.";
      if (r) r.reasons.unshift(note);
      else
        r = {
          risky: true,
          level: "medium",
          code: "exposed-site",
          title: "Wallet request on an exposed site",
          reasons: [note, "Check every detail in your wallet before approving."],
          f: {},
        };
    }
    return r;
  }

  // ---- ClickFix clipboard commands ---------------------------------------------------
  // Tier "critical": essentially never a legitimate thing for a web page to copy.
  // Tier "install": also used by real docs -> pass when it is visibly shown in a code block.
  const CRITICAL = new RegExp(
    [
      "\\bmshta\\b",
      "rundll32",
      "regsvr32",
      "bitsadmin",
      "certutil",
      "\\bwscript\\b",
      "\\bcscript\\b",
      "start-bitstransfer",
      "downloadstring",
      "downloadfile",
      "add-type",
      "-e(nc(odedcommand)?)?\\s+[A-Za-z0-9+/=]{20,}",
      "-enc(odedcommand)?\\s+[A-Za-z0-9+/=]{20,}",
      "base64\\s+(-d|-D|--decode)",
      "\\$\\([^)]*base64",
      "osascript\\s+-e",
      "\\bnc\\s+-e\\b",
      "/dev/tcp/",
      "\\bfinger\\s+\\S+@\\S+",
      "\\|\\s*cmd\\b",
      "-w(indowstyle)?\\s+h(idden)?\\b",
      "-nop\\b.*-w\\b",
      "frombase64string",
      "invoke-restmethod[^\\n|]*\\|\\s*iex",
    ].join("|"),
    "i"
  );
  const INSTALL = new RegExp(
    [
      "powershell",
      "pwsh",
      "invoke-expression",
      "\\biex\\b",
      "start-process",
      "invoke-webrequest",
      "\\birm\\b",
      "cmd(\\.exe)?(\\s+/[a-z]:?\\S*)*\\s+/[ck]\\b",
      "(curl|wget)[^\\n|]*\\|\\s*(sudo\\s+)?(ba|z)?sh",
      "\\$\\(\\s*(curl|wget)\\b",
    ].join("|"),
    "i"
  );

  const normalise = (text) =>
    String(text)
      .replace(/[\^`"']/g, "")
      .replace(/\s+/g, " ")
      .trim();

  function clipboardTier(text) {
    if (typeof text !== "string" || text.length < 6 || text.length > 4000) return null;
    const t = normalise(text);
    if (CRITICAL.test(t)) return "critical";
    if (INSTALL.test(t)) return "install";
    return null;
  }

  function classifyClipboard(text) {
    const tier = clipboardTier(text);
    if (!tier) return null;
    return {
      level: "high",
      code: "clickfix",
      title: "A website put a command in your clipboard",
      reasons: [
        'This is the ClickFix trick: a fake "verify you are human" or "fix this error" page asks you to paste a command into Run, Terminal or PowerShell.',
        "PHProtect replaced it with a harmless notice. Never paste commands a website hands you.",
      ],
      f: { count: tier === "critical" ? 1 : 0 },
    };
  }

  const api = {
    classify,
    classifyCall,
    classifyTypedData,
    classifyPersonalSign,
    classifyClipboard,
    clipboardTier,
    scanCalls,
    WALLET_ACTION,
    HUGE,
    CHAINS,
    safeAddr,
    safeName,
    chainId,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else globalThis.PHProtectRules = api;
})();
