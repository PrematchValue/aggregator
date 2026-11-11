# Collect / Refresh safeguards

The existing Gist ID, output filenames, secret references, schedules, and shared
workflow concurrency group are unchanged. Collect still runs weekly; Refresh
still runs every two hours. Neither workflow requires new secrets.

## Discovery budget

Refresh only reads existing subscriptions. If they all fail, the run exits with
an error and leaves the publication intact; it never starts airport discovery.

Collect defaults to 50 Telegram pages and at most 100 candidate airports. The
budget is applied before backend resolution and registration-requirement probes,
and again before creating registration tasks. Hosts with working subscriptions
and duplicate frontends/backends are skipped. Overwrite replaces the historical
catalogue with the current discovery result instead of merging all old entries.
An unsuccessful discovery does not trigger a full historical scan. Custom sites
remain supported and share the final registration budget. The monthly article
source reads only the latest three discovered months in budgeted mode; redirect
expansion is also capped. Other callers of discovery retain their existing defaults.

`--max-candidates N` changes the positive per-run budget. Sources are processed in
their existing order, so the budget deliberately favors the first recent results;
it does not guarantee exhaustive coverage or persistent failure backoff.

## Node checks

Protocol/credential/port structure is validated using the existing outbound
validators, even with `--skip`. Direct/reject routes are not counted as nodes.
Both workflows also use `--probe-sample 50`: up to 50 randomly sampled nodes get
an advisory TCP connection check. Only TCP-capable protocols are tested. DNS
answers must all be public, and connections use those resolved addresses directly
to avoid DNS rebinding into private networks. Connections time out after two
seconds per address, try at most two addresses, and use at most 16 workers.
DNS resolution uses the operating system resolver and its timeout.

The report contains counts only. A TCP connection does not prove proxy
authentication, routing, or China-side usability. Failure is **unknown**, not
evidence to delete a node. UDP protocols are skipped. The existing explicit
`--no-skip` liveness mode remains available; the workflows keep `--skip`.

## Publication gate

Before collecting, read an authenticated, uncached Gist snapshot. Missing access,
malformed responses, or incomplete/truncated content that cannot be retrieved
abort the run. A genuinely empty Gist can still be initialized.

All requested formats must convert successfully to fresh, nonempty output.
Clash YAML, Sing-box JSON, V2Ray/mixed URI content, and Surge proxy entries receive format checks.
Clash nodes receive protocol structure validation; other optional formats receive
only a basic nonempty/error-document check. Existing output files are never used
as a successful conversion result.

Publication is blocked when no successful source remains, fewer than half the
previous source URLs succeed, or any default-format node count falls below half
its previous value. New sources cannot hide failure of the previous source set.
Exactly half is allowed. A legitimate large reduction will also be blocked and
requires investigation; there is no automatic bypass.

Immediately before publishing, read the Gist again and reject a changed revision.
Publish all artifacts and source URLs together using the existing single Gist
PATCH, then replace local output/source files only after a successful upload.
The shared workflow queue prevents Collect/Refresh races. The revision check is
not a server-side compare-and-swap: an unrelated external writer can still race
in the short interval between the last read and PATCH.

Failures exit nonzero for visibility in Actions. No production workflow or Gist
write is needed to run the regression suite:

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Tests mock external collection, conversions, and Gist access; they cover both
successful publication and failure paths without accessing real credentials.
