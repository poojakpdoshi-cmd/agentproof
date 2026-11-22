# Phase 6: live Gemini + BAND Red → Blue → retest runbook

Status: **ready for an authorized operator; not yet run.** No Gemini request has been made.
Fixture and offline runs are not proof of autonomy. Only `docs/phase6-live.json` from this
procedure is.

## Validated locally (no network)
- `.env` contains all six `BAND_*` values and `GEMINI_API_KEY`, and `AI_PROVIDER=gemini`.
- `config()` currently fails with `Missing: GEMINI_MODEL`. Both opt-in flags are `false`.
  Both are intentional until the operator authorizes the run.
- The stored Gemini key is **not in the classic Google AI Studio format** (`AIza…`, 39
  characters). Its format matches Vertex AI express-mode keys. The adapter calls only the
  Gemini Developer API (`generativelanguage.googleapis.com`), so the key may be rejected.
  Vertex AI may also involve billing. This is unverified without a request.
- BAND authentication and Red ↔ Blue transport were verified live in Phase 4.1.
- New: `agents/band.ts` records sanitized live evidence to `docs/phase6-live.json`. It
  records each received message, the findings and the retest report. Platform IDs become
  role labels plus 12-character SHA-256 fingerprints. A write is refused if any key or ID
  value would appear, and errors are path-scrubbed.

## Operator pre-flight (authorized, age-eligible operator only)
1. Confirm you are eligible to use the Gemini API and accept its terms.
2. In Google AI Studio, use a **Gemini API key** from a project with **billing disabled**.
   Replace `GEMINI_API_KEY` in `.env` if the current key is a Vertex AI key.
3. Choose a model listed for the free tier on AI Studio's rate-limit page. Prefer one with
   thinking off or minimal: thinking tokens can exhaust the 1,500-token output cap, which
   fails closed.
4. Edit `.env` only (never commit it):
   ```dotenv
   GEMINI_MODEL=<free-tier model ID starting with gemini->
   GEMINI_LIVE_ENABLED=true
   GEMINI_FREE_TIER_CONFIRMED=true
   ```
5. Offline configuration check (makes no network request):
   ```sh
   node --env-file=.env --input-type=module -e "const b=await import('./agents/band.ts');const g=await import('./agents/gemini.ts');b.config(process.env);g.geminiModel(process.env);console.log('config OK')"
   ```
6. Run `npm test` and expect 134 passing.

## Live run
1. Start: `npm run agents:live`. It stays running and prints nothing on success. A failure
   prints a fixed "Live run blocked" line and exits 2.
2. In the BAND web app, in the configured private room and as the configured owner, send a
   message that mentions Red and ends with `start` (for example `@Red start`).
3. Wait. There are at least 15 s between Gemini requests: up to 6 for Red (about 1.5 min),
   then up to 3 for Blue. Blue then posts its retest report to the owner.
4. Stop with Ctrl+C. The budget is 9 Gemini requests per process, so a second run needs a
   restart. HTTP 429 or any provider failure stops the session with no retry. Investigate
   before restarting.

Do not screen-record the BAND UI or terminal output that shows IDs or keys.

## Evidence collection
1. Review `docs/phase6-live.json`. Expected events: Red `received` → Red `findings-sent`
   → Blue `received` → Blue `retest-report-sent`. The payload `source` must be
   `gemini:<model>`.
2. Check that no `.env` value appears in the file:
   ```sh
   node -e "const f=require('fs');const t=f.readFileSync('docs/phase6-live.json','utf8');const v=f.readFileSync('.env','utf8').split(/\r?\n/).map(l=>l.slice(l.indexOf('=')+1).trim()).filter(x=>x.length>=8);console.log(v.some(x=>t.includes(x))?'LEAK':'clean')"
   ```
3. Record the outcome honestly, including failure (no finding, rejected proposals, or a
   stopped session). Commit the evidence only after review. Never substitute fixture output.

## Remaining limits
Model quality, BAND turn time limits during a long Red turn, and whether the platform
keeps message content unchanged for Blue's JSON parsing are only verified by this run.
