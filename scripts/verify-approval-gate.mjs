// Deterministic oracle for the interactive approval gate (src/approval.ts), review finding P1 "one human
// 'y' approves every concurrently pending gated call".
//
// 0.1.0 opened a new readline interface on the shared stdin for EVERY pending call, and every interface
// received the same input line. A batch_call with three gated calls (two writes and a destructive one)
// printed three prompts, one 'y' answered all of them, and all three executed.
//
// The gate now serialises prompts through ONE queue and one interface: only the head prompt is shown, it
// carries a fresh random code, and only that exact code approves it (a bare 'y', a wrong code, type-ahead
// and EOF all deny). One typed line can therefore resolve at most one prompt, and a line typed before the
// prompt existed can never approve anything.
//
// STATUS (design 3.3). The in-band TTY gate is no longer on the call path: the Router creates out-of-band, argument-bound
// approvals instead (src/approvals.ts, proven by verify-approvals). Sections 1 to 5 and 7 still exercise the legacy
// module src/approval.ts on its own, unchanged, and keep guarding it for as long as it is exported. Section 6, the
// end-to-end Router case, was ADAPTED to the new contract (see there).
//
// This oracle plays the human against the REAL gate in a child process whose stdin and stdout look like a
// terminal (scripts/fixtures/approval-child.mjs). It proves:
//   concurrency   N concurrent approvals show ONE prompt at a time; one bare 'y' approves none; one code
//                 approves exactly the prompt it was shown for; a wrong code denies and the next prompt
//                 gets its own fresh code; piled-up type-ahead approves nothing
//   fail closed   EOF on stdin denies every pending call and the process is not left hanging; a flood is
//                 bounded (calls beyond the queue limit are refused at once); spoofed prompt text in a tool
//                 name is neutralised
//   end to end    the real Router: a batch_call of three gated calls prints no prompt, executes nothing, and a
//                 typed 'y' or code approves nothing (adapted: it used to execute exactly one call per code)
//   unchanged     SWITCHBOARD_AUTO_APPROVE=1 still approves, a non-TTY still denies (fail closed), an
//                 active stdio transport still denies
// Zero deps (node stdlib + the package's compiled output + its bundled MCP SDK). Build first.
// Isolated SWITCHBOARD_HOME; no network; every child is killed.
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tmp = mkdtempSync(join(tmpdir(), "sb-approval-"));
const homeRoot = join(tmp, "home");
const SBHOME = join(homeRoot, ".switchboard");
mkdirSync(SBHOME, { recursive: true });
for (const d of ["appdata", "local"]) mkdirSync(join(tmp, d), { recursive: true });
process.env.SWITCHBOARD_HOME = SBHOME;
process.env.HOME = homeRoot;
process.env.USERPROFILE = homeRoot;
process.env.APPDATA = join(tmp, "appdata");
process.env.LOCALAPPDATA = join(tmp, "local");
delete process.env.SWITCHBOARD_AUTO_APPROVE;
delete process.env.SWITCHBOARD_INSECURE_APPROVAL;

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  const clean = String(detail).replace(/\x1b\[[0-9;]*[A-Za-z]/g, "").replace(/\s+/g, " ").trim();
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${clean ? `: ${clean}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const approval = await import(pathToFileURL(join(root, "dist", "approval.js")).href);

const CODE_PROMPT = /Type ([A-Z2-7]{4}) to allow/;
const ANY_PROMPT = /Type ([A-Z2-7]{4}) to allow|Allow this call/;

/**
 * Run the approval fixture and let `script` play the human. `h.waitFor(re)` finds the next match in the
 * child's stdout after the previous match (null on timeout), `h.send(text)` types, `h.end()` closes stdin.
 */
async function drive(args, script, { deadlineMs = 20_000, env = {} } = {}) {
  const child = spawn(process.execPath, [join(root, "scripts", "fixtures", "approval-child.mjs"), ...args], {
    cwd: root,
    env: { ...process.env, NO_COLOR: "1", ...env },
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  let stdout = "";
  let stderr = "";
  let exitCode = null;
  let exited = false;
  child.stdout.setEncoding("utf8").on("data", (d) => (stdout += d));
  child.stderr.setEncoding("utf8").on("data", (d) => (stderr += d));
  child.stdin.on("error", () => {});
  const exitP = new Promise((resolve) =>
    child.on("exit", (c) => {
      exited = true;
      exitCode = c;
      resolve();
    }),
  );
  let cursor = 0;
  const h = {
    get stdout() {
      return stdout;
    },
    get childExited() {
      return exited;
    },
    sleep,
    async waitFor(re, ms = 6_000) {
      const t0 = Date.now();
      while (Date.now() - t0 < ms) {
        const rest = stdout.slice(cursor);
        const m = re.exec(rest);
        if (m) {
          cursor += m.index + m[0].length;
          return m;
        }
        if (exited) return null;
        await sleep(25);
      }
      return null;
    },
    send(text) {
      try {
        child.stdin.write(text);
      } catch {
        /* child already gone */
      }
    },
    end() {
      try {
        child.stdin.end();
      } catch {
        /* child already gone */
      }
    },
  };
  const deadline = setTimeout(() => {
    try {
      child.kill("SIGKILL");
    } catch {
      /* gone */
    }
  }, deadlineMs);
  let scriptError = null;
  try {
    await script(h);
  } catch (err) {
    scriptError = err;
  }
  // give the child a moment to finish on its own: a gate that hangs on EOF is a finding in itself
  await Promise.race([exitP, sleep(4_000)]);
  const exitedOnItsOwn = exited;
  if (!exited) {
    try {
      child.kill("SIGKILL");
    } catch {
      /* gone */
    }
    await Promise.race([exitP, sleep(1_000)]);
  }
  clearTimeout(deadline);
  const line = (tag) => {
    const l = stderr.split(/\r?\n/).find((x) => x.startsWith(`${tag} `));
    try {
      return l ? JSON.parse(l.slice(tag.length + 1)) : null;
    } catch {
      return null;
    }
  };
  return { stdout, stderr, exitCode, exitedOnItsOwn, scriptError, result: line("RESULT"), early: line("EARLY") };
}

const promptCount = (s) => (s.match(/Type [A-Z2-7]{4} to allow/g) ?? []).length;
const approved = (r) => (r.result?.results ?? []).filter((v) => v === true).length;

// =====================================================================================================
// 1. three concurrent approvals, a bare 'y'
// =====================================================================================================
{
  const r = await drive(["direct", "3"], async (h) => {
    await h.waitFor(/\[approval\]/);
    await h.sleep(700);
    h.send("y\n");
    await h.sleep(1_500);
    h.end();
  });
  assert("1 three concurrent approvals, one bare 'y': none is approved (it approved all three)", r.result && approved(r) === 0, `results ${JSON.stringify(r.result?.results)}`);
}

// =====================================================================================================
// 2. the code approves exactly the prompt it was shown for
// =====================================================================================================
{
  let m1 = null;
  let m2 = null;
  let shownBefore = -1;
  let header1 = "";
  const r = await drive(["direct", "3"], async (h) => {
    m1 = await h.waitFor(CODE_PROMPT);
    await h.sleep(500); // time for any second prompt to appear if the gate were not serialising
    shownBefore = promptCount(h.stdout);
    header1 = (h.stdout.match(/\[approval\][^\n]*/) ?? [""])[0];
    if (m1) h.send(`${m1[1]}\n`);
    m2 = await h.waitFor(CODE_PROMPT);
    h.end();
  });
  assert("2 the prompt carries a 4 character code to type", !!m1, m1 ? "" : "no 'Type XXXX to allow' prompt");
  assert("2 only one prompt is on screen while three calls wait", shownBefore === 1, `prompts shown ${shownBefore}`);
  assert("2 the first prompt is for the first call (FIFO) and names server and tool", /gated/.test(header1) && /tool_0/.test(header1), header1);
  assert("2 typing the code approves exactly that call and no other", r.result && approved(r) === 1 && r.result.results[0] === true, `results ${JSON.stringify(r.result?.results)}`);
  assert("2 the next prompt appears after the first is answered, with a different code", !!m2 && !!m1 && m2[1] !== m1[1], `${m1?.[1]} then ${m2?.[1]}`);
  assert("2 closing the terminal denies the calls still waiting", r.result && r.result.results[1] === false && r.result.results[2] === false);
}

// =====================================================================================================
// 3. type-ahead approves nothing
// =====================================================================================================
{
  const r = await drive(["direct", "3"], async (h) => {
    await h.waitFor(ANY_PROMPT);
    h.send("y\ny\nyes\nY\ny\n");
    await h.sleep(1_200);
    h.end();
  });
  assert("3 five lines of y/yes typed in one go approve none of three pending calls", r.result && approved(r) === 0, `results ${JSON.stringify(r.result?.results)}`);
}

// =====================================================================================================
// 4. a wrong answer denies that prompt only; the next prompt gets its own code
// =====================================================================================================
{
  let c1 = null;
  let c2 = null;
  const r = await drive(["direct", "3"], async (h) => {
    c1 = await h.waitFor(CODE_PROMPT);
    h.send("0000\n"); // '0' is not in the code alphabet, so this can never be the code
    c2 = await h.waitFor(CODE_PROMPT);
    if (c2) h.send(`${c2[1].toLowerCase()}\n`); // codes are not case sensitive
    await h.waitFor(CODE_PROMPT);
    h.end();
  });
  assert("4 a wrong code denies the first call, the second code approves the second, the third is denied", r.result && JSON.stringify(r.result.results) === "[false,true,false]", `results ${JSON.stringify(r.result?.results)}`);
  assert("4 every prompt gets its own fresh code", !!c1 && !!c2 && c1[1] !== c2[1], `${c1?.[1]} then ${c2?.[1]}`);
}

// =====================================================================================================
// 5. EOF, flood and spoofing
// =====================================================================================================
{
  const r = await drive(["direct", "3"], async (h) => {
    await h.waitFor(ANY_PROMPT);
    h.end();
  });
  assert("5 EOF on stdin denies every pending call and the process finishes on its own (no hang)", r.exitedOnItsOwn && r.result && approved(r) === 0 && r.result.results.length === 3, `exited on its own ${r.exitedOnItsOwn}, results ${JSON.stringify(r.result?.results)}`);

  const MAX = approval.MAX_PENDING_PROMPTS;
  assert("5 approval exports MAX_PENDING_PROMPTS (a number between 4 and 64)", Number.isInteger(MAX) && MAX >= 4 && MAX <= 64, String(MAX));
  const flood = await drive(["direct", "40"], async (h) => {
    await h.waitFor(ANY_PROMPT);
    await h.sleep(900);
    h.end();
  });
  assert("5 a flood of 40 gated calls: everything beyond the queue limit is refused at once, nothing is approved", Number.isInteger(MAX) && flood.early?.settled === 40 - MAX && flood.result && approved(flood) === 0, `refused early ${flood.early?.settled}, expected ${40 - MAX}, approved ${approved(flood)}`);

  let spoofOut = "";
  await drive(["spoof"], async (h) => {
    await h.waitFor(ANY_PROMPT);
    await h.sleep(300);
    spoofOut = h.stdout;
    h.end();
  });
  assert("5 a tool name with a newline cannot start a forged '[approval]' line", !/\n\[approval\] FAKE/.test(spoofOut), JSON.stringify(spoofOut.slice(0, 160)));
  assert("5 a tool name cannot send a clear-screen escape to the terminal", !spoofOut.includes("\u001b[2J"));
}

// =====================================================================================================
// 6. end to end through the real Router: batch_call with three gated calls
//
// ADAPTED for design 3.3. Before: the Router prompted on the terminal, so one 'y' approved all three calls (0.1.0)
// and, after the fix, one typed code approved exactly the call it was shown for. Now the Router has no in-band
// channel: a gated call returns SB_APPROVAL_PENDING and leaves a request only the owner can decide out of band
// (dashboard or `switchboard approvals`, each behind a gateway-side presence check, proven by verify-approvals).
// So the contract this section pins is: no prompt appears, nothing executes, every call is told how to proceed,
// and nothing typed at the terminal approves anything. The old "a code executes exactly one call" check has no
// counterpart here (the channel it exercised is gone); "an approval executes exactly one call" is in verify-approvals.
// =====================================================================================================
{
  const quiet = await drive(["router-batch"], async (h) => {
    await h.sleep(1_200);
    h.end();
  });
  assert("6 batch_call of 3 gated calls (2 writes, 1 destructive): the Router prints no in-band prompt", !/\[approval\]|Type [A-Z2-7]{4} to allow/.test(quiet.stdout), JSON.stringify(quiet.stdout.slice(0, 120)));
  assert("6 ...and nothing executes (it executed all 3 in 0.1.0)", quiet.result && quiet.result.executed.length === 0, `executed ${JSON.stringify(quiet.result?.executed)}`);
  assert("6 ...each of the three calls comes back SB_APPROVAL_PENDING (told how to proceed), none is silently dropped", quiet.result?.pending === 3, `pending ${quiet.result?.pending}`);

  const typed = await drive(["router-batch"], async (h) => {
    await h.sleep(500);
    h.send("y\ny\nABCD\n");
    await h.sleep(1_000);
    h.end();
  });
  assert("6 a 'y' and a code typed at the terminal approve nothing", typed.result && typed.result.executed.length === 0 && typed.result.pending === 3, `executed ${JSON.stringify(typed.result?.executed)} pending ${typed.result?.pending}`);
}

// =====================================================================================================
// 7. unchanged behaviour
// =====================================================================================================
{
  const { approve, setStdioActive } = approval;
  process.stdin.isTTY = false;
  process.stdout.isTTY = false;
  delete process.env.SWITCHBOARD_AUTO_APPROVE;
  assert("7 no TTY: denied (fail closed), no prompt", (await approve("s", "t", "write", "r")) === false);
  process.env.SWITCHBOARD_AUTO_APPROVE = "1";
  assert("7 SWITCHBOARD_AUTO_APPROVE=1: approved", (await approve("s", "t", "write", "r")) === true);
  delete process.env.SWITCHBOARD_AUTO_APPROVE;
  process.stdin.isTTY = true;
  process.stdout.isTTY = true;
  setStdioActive(true);
  assert("7 stdio transport active: denied even on a TTY (stdin is the JSON-RPC channel)", (await approve("s", "t", "write", "r")) === false);
  setStdioActive(false);
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
