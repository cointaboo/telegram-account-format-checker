# Telegram Account Format Checker

Validate a batch of Telegram account credentials **before** you import them into a session pool, a CRM, or a bulk-import pipeline.

Catches the three failure modes that quietly poison a pool:

| Problem | Why it matters |
|---|---|
| Phone without `+` / wrong length for its country code | login requests silently fail or go to the wrong account |
| `StringSession` that is truncated, not base64, or too short to hold an auth key | `UnauthorizedError` on every use, hours later |
| Duplicate phone or duplicate session blob | two workers talking over one account, flood bans |

Pure stdlib. No `telethon`, no network calls, nothing to install.

## Install

```bash
git clone https://github.com/cointaboo/telegram-account-format-checker
cd telegram-account-format-checker
# nothing to install — Python 3.9+ stdlib only
```

## Use

```bash
python3 tg_check.py accounts.csv
python3 tg_check.py accounts.csv --json report.json
python3 tg_check.py accounts.csv --strict      # warnings become failures
```

CSV needs a header. Column order is free; extra columns are ignored.

```csv
phone,session,password
+915555555555,1BVtsOK4u...,pw1
+8801700000000,1BVtsOK4v...,pw2
```

```
ERROR  line 4  phone     missing leading '+' / country code
ERROR  line 5  session   only 3 chars — StringSession is typically 300+
WARN   line 3  password  no password — 2FA may be off or not recorded

4 rows | 2 usable | 2 errors | 1 warnings
```

Exit code `0` = every row is importable. `1` = at least one hard error (or any warning under `--strict`), so it drops straight into CI.

## What each check does

**`check_phone`** — normalises `00` prefixes, then requires E.164 (`+<digits>`, 7–15 total). For known country codes it also checks the national-number length, which is where most bad rows hide: `+91` needs 10 digits, `+86` needs 11, `+880` needs 10.

**`check_session`** — a Telethon `StringSession` is base64url over a serialised auth key, so it should decode to a few hundred bytes. Anything under 100 characters is truncated; anything that fails to decode is not a session at all.

**Duplicate detection** — two rows with the same phone or the same session blob will collide at runtime. The tool reports the first occurrence's line number so you can fix the right row.

## Why this exists

Extracted from the account-onboarding pipeline we run for the shop at [yuantou.one](https://yuantou.one), where a few thousand accounts a month get checked before they reach a worker. The length tables and the base64 shape check are the parts that actually saved us from flooding failures; the rest is plumbing.

No pricing, no infrastructure details, no credentials — just the format logic.

## License

MIT
