# Try it without a robot

No robot needed to see it work - point it at a throwaway local HTTP server
instead of a real device. Requires local Postgres running (`psql -d glitched`
should connect) and this repo's `.venv` set up.

**Prerequisites:** Glitched installed (see [Install](install.md)), with the
threat intel loaded.

**1. Start a throwaway "device".** Nothing real is connected - this is just
something for the passive checks to observe:

```bash
python -m http.server 8080 --bind 127.0.0.1 &
SERVER_PID=$!
```

**2. Create the assessment.** `glitched create` prints the new assessment's
id (`created assessment <N> for ...`) - capture it into a variable so the rest
of the commands don't need it typed in by hand:

```bash
glitched create --target-name "sample" --host 127.0.0.1 \
  --authorization "demo run against a local stand-in, no real device involved"

ASSESSMENT_ID=$(psql -d glitched -Atc "SELECT max(id) FROM assessments;")
```

**3. Plan, run, report, and grade the posture:**

```bash
glitched plan $ASSESSMENT_ID --all     # writes a finding for all 81 EMB3D threats
glitched run $ASSESSMENT_ID            # auto-runs the passive checks
glitched report $ASSESSMENT_ID         # full breakdown, evidence-backed
glitched posture $ASSESSMENT_ID        # security-posture grade + coverage
```

**4. Stop the throwaway server:**

```bash
kill $SERVER_PID
```

**Expected result:** 81 findings planned, 3 passive checks run automatically
(TID-406, TID-408, TID-411), the rest gated `awaiting_approval` since they
need physical access, credentials, or judgment calls this agent won't make
unattended. Against the plain `http.server` stand-in, TID-406 and TID-408
come back `confirmed` (it really is an unauthenticated plaintext service) and
TID-411 comes back `inconclusive` (no TLS port to evaluate at all). `posture`
then grades it **AT RISK** at ~4% coverage - honest, because 78 threats are
still unreviewed and are counted as unverified, not as safe.

**Clean up the sample data** once you've seen the report (otherwise it stays
in the same `glitched` database your real assessments use):

```bash
psql -d glitched -c "DELETE FROM assessments WHERE target_name='sample';"
rm -rf evidence/
```
