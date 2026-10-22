"use strict";
// Seed Shield detection. The wordlist is real BIP39; the cases are the shapes
// a phishing page actually produces.
const test = require("node:test");
const assert = require("node:assert/strict");
require("../src/bip39.js");
const G = require("../src/guard.js");

const SEED12 =
  "abandon ability able about above absent absorb abstract absurd abuse access accident";
const SEED24 =
  `${SEED12} account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent`
    .split(" ")
    .slice(0, 24)
    .join(" ");

const el = (props) => ({
  name: "",
  id: "",
  placeholder: "",
  type: "text",
  labels: null,
  closest: null,
  getAttribute: (n) => (props.attrs && props.attrs[n]) || "",
  ...props,
});

test("tokeniser drops numbering and punctuation", () => {
  assert.deepEqual(G.tokens("1. abandon 2. ability 3. able"), ["abandon", "ability", "able"]);
  assert.deepEqual(G.tokens("  WALLET,   seed "), ["wallet", "seed"]);
  assert.deepEqual(G.tokens(null), []);
});

test("a pasted 12 or 24 word phrase is recognised", () => {
  assert.equal(G.looksLikePastedSeed(SEED12), true);
  assert.equal(G.looksLikePastedSeed(SEED24), true);
  assert.equal(G.looksLikePastedSeed(`seed: ${SEED12}`), true);
});

test("pasted prose with too few seed words is left alone", () => {
  assert.equal(G.looksLikePastedSeed("abandon ability able about above absent"), false);
  assert.equal(G.looksLikePastedSeed(""), false);
  assert.equal(G.looksLikePastedSeed(SEED12 + " " + "zzz ".repeat(30)), false);
});

test("typing a whole short seed trips at the normal threshold", () => {
  assert.equal(G.looksLikeTypedSeed("abandon ability able about above absent", 6), true);
  assert.equal(G.looksLikeTypedSeed("abandon ability able about above", 6), false);
  assert.equal(G.looksLikeTypedSeed(SEED12, 6), true);
});

test("a long run at the end trips even after prose", () => {
  assert.equal(
    G.looksLikeTypedSeed("my words are abandon ability able about above absent absorb abstract", 6),
    true
  );
  assert.equal(
    G.looksLikeTypedSeed("my words are abandon ability able about above absent absorb abstract", 6),
    true
  );
});

test("seed-labelled fields use the lower three-word threshold", () => {
  assert.equal(G.looksLikeTypedSeed("abandon ability able", 3), true);
  assert.equal(G.looksLikeTypedSeed("abandon ability", 3), false);
});

test("very long fields are ignored", () => {
  assert.equal(G.looksLikeTypedSeed("abandon ".repeat(400), 6), false);
});

test("field hints classify the common shapes", () => {
  assert.equal(G.fieldHint(el({ name: "seedPhrase" })), "seed");
  assert.equal(G.fieldHint(el({ attrs: { "aria-label": "Mnemonic" } })), "seed");
  assert.equal(G.fieldHint(el({ placeholder: "Recovery phrase" })), "seed");
  assert.equal(G.fieldHint(el({ type: "password" })), "password");
  assert.equal(G.fieldHint(el({ type: "search" })), "search");
  assert.equal(G.fieldHint(el({ name: "q" })), "search");
  assert.equal(G.fieldHint(el({ id: "query" })), "search");
  assert.equal(G.fieldHint(el({})), "normal");
});

test("field hints survive odd elements", () => {
  assert.equal(G.fieldHint(el({ name: "word #7" })), "seed");
  assert.equal(G.fieldHint(el({ labels: [] })), "normal");
});
