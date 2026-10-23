// A worker process for verify-storage.mjs: it holds its OWN ApiKeyStore on a shared home and verifies two
// tokens in a tight loop for a fixed time, recording the start time of every verify that returned true
// for the token the parent revokes mid-run. Output: one JSON line. Tokens are obviously fake test values
// issued by the oracle into a throwaway SWITCHBOARD_HOME.
//
// argv: <home> <revokedToken> <keptToken> <runMs>
import { ApiKeyStore } from "../../dist/apikeys.js";

const [home, revoked, kept, runMs] = process.argv.slice(2);
const store = new ApiKeyStore({ home, lastUsedIntervalMs: 0 }); // persist last_used on EVERY verify: maximum write pressure
const end = Date.now() + Number(runMs);
const revokedTrueAt = [];
let keptTrue = 0;
let iterations = 0;
let errors = 0;
while (Date.now() < end) {
  iterations++;
  const t0 = Date.now();
  try {
    if (store.verify(revoked)) revokedTrueAt.push(t0);
    if (store.verify(kept)) keptTrue++;
  } catch {
    errors++;
  }
}
console.log(JSON.stringify({ iterations, errors, keptTrue, revokedTrueAt }));
