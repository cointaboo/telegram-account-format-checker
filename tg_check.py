#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Telegram account credential validator.

Checks a list of account rows before bulk import:

  * phone number format (E.164, with country-code sanity)
  * StringSession blob (base64 shape, decodable, expected length class)
  * duplicate detection (same phone, same session)
  * optional 2FA password presence

No network calls, no Telethon dependency — pure stdlib, so it runs on a
box that has nothing installed.

Usage:
    python3 tg_check.py accounts.csv
    python3 tg_check.py accounts.csv --json report.json
    python3 tg_check.py accounts.csv --strict      # fail on warnings too

CSV columns (header required, order free):
    phone, session, password
Extra columns are ignored.

Output: one line per problem + a summary. Exit code 0 = all rows usable,
1 = at least one hard error (or any warning with --strict).
"""
import argparse
import base64
import binascii
import csv
import json
import re
import sys

E164 = re.compile(r"^\+[1-9]\d{6,14}$")
COUNTRY_MIN = {
    "1": 10, "7": 10, "20": 10, "27": 9, "30": 10, "31": 9, "32": 9,
    "33": 9, "34": 9, "36": 9, "39": 9, "40": 9, "41": 9, "43": 10,
    "44": 10, "45": 8, "46": 9, "47": 8, "48": 9, "49": 10, "51": 9,
    "52": 10, "53": 8, "54": 10, "55": 10, "56": 9, "57": 10, "58": 10,
    "60": 9, "61": 9, "62": 9, "63": 10, "64": 8, "65": 8, "66": 9,
    "81": 10, "82": 9, "84": 9, "86": 11, "90": 10, "91": 10, "92": 10,
    "98": 10, "212": 9, "213": 9, "216": 8, "218": 9, "220": 7, "221": 9,
    "233": 9, "234": 10, "249": 9, "254": 9, "255": 9, "256": 9, "263": 9,
    "380": 9, "420": 9, "880": 10, "886": 9, "961": 8, "962": 9, "964": 10,
    "966": 9, "971": 9, "972": 9, "977": 10, "998": 9,
}


def check_phone(v):
    """Return (ok, code, msg)."""
    v = (v or "").strip().replace(" ", "").replace("-", "")
    if not v:
        return False, "empty", "phone is empty"
    if v.startswith("00"):
        v = "+" + v[2:]
    if not v.startswith("+"):
        if v.isdigit():
            return False, "no_cc", "missing leading '+' / country code"
        return False, "junk", "non-numeric characters"
    if not E164.match(v):
        return False, "format", "does not match E.164 (+<digits>, 7-15 digits)"
    digits = v[1:]
    for cc in sorted(COUNTRY_MIN, key=len, reverse=True):
        if digits.startswith(cc):
            rest = len(digits) - len(cc)
            need = COUNTRY_MIN[cc]
            if rest == need:
                return True, "ok", ""
            if rest < need:
                return False, "short", "national number too short for +%s" % cc
            return False, "long", "national number too long for +%s" % cc
    return True, "ok", "unknown country code, format is valid"


def check_session(v):
    """StringSession is base64url of a serialised auth key."""
    v = (v or "").strip()
    if not v:
        return False, "empty", "session is empty"
    if len(v) < 100:
        return False, "short", "only %d chars — StringSession is typically 300+" % len(v)
    if len(v) > 1200:
        return False, "long", "%d chars — larger than expected for StringSession" % len(v)
    pad = v + "=" * (-len(v) % 4)
    try:
        raw = base64.urlsafe_b64decode(pad.encode())
    except (binascii.Error, ValueError):
        try:
            raw = base64.b64decode(pad.encode())
        except Exception:
            return False, "b64", "not valid base64"
    if len(raw) < 200:
        return False, "tiny", "decoded payload is only %d bytes" % len(raw)
    return True, "ok", ""


def load(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        rd = csv.DictReader(f)
        if not rd.fieldnames:
            raise SystemExit("CSV has no header row")
        cols = {c.lower().strip(): c for c in rd.fieldnames}
        if "phone" not in cols:
            raise SystemExit("CSV needs a 'phone' column")
        rows = []
        for i, r in enumerate(rd, 2):
            rows.append({
                "line": i,
                "phone": (r.get(cols.get("phone", ""), "") or "").strip(),
                "session": (r.get(cols.get("session", ""), "") or "").strip(),
                "password": (r.get(cols.get("password", ""), "") or "").strip(),
            })
    return rows


def main():
    ap = argparse.ArgumentParser(description="Validate Telegram account credentials.")
    ap.add_argument("csv")
    ap.add_argument("--json", metavar="PATH", help="write machine-readable report")
    ap.add_argument("--strict", action="store_true", help="treat warnings as failures")
    a = ap.parse_args()

    rows = load(a.csv)
    errors, warnings = [], []
    seen_phone, seen_sess = {}, {}

    for r in rows:
        ok, code, msg = check_phone(r["phone"])
        if not ok:
            errors.append({"line": r["line"], "field": "phone", "code": code, "msg": msg})
        else:
            key = r["phone"]
            if key in seen_phone:
                warnings.append({"line": r["line"], "field": "phone", "code": "dup",
                                 "msg": "duplicate of line %d" % seen_phone[key]})
            else:
                seen_phone[key] = r["line"]
            if not r["password"]:
                warnings.append({"line": r["line"], "field": "password", "code": "no_2fa",
                                 "msg": "no password — 2FA may be off or not recorded"})

        if r["session"]:
            ok, code, msg = check_session(r["session"])
            if not ok:
                errors.append({"line": r["line"], "field": "session", "code": code, "msg": msg})
            else:
                k = r["session"]
                if k in seen_sess:
                    warnings.append({"line": r["line"], "field": "session", "code": "dup_sess",
                                     "msg": "same session as line %d" % seen_sess[k]})
                else:
                    seen_sess[k] = r["line"]

    for e in errors:
        print("ERROR  line %d  %-8s  %s" % (e["line"], e["field"], e["msg"]))
    for w in warnings:
        print("WARN   line %d  %-8s  %s" % (w["line"], w["field"], w["msg"]))

    ok_rows = len(rows) - len({e["line"] for e in errors})
    print("\n%d rows | %d usable | %d errors | %d warnings"
          % (len(rows), ok_rows, len(errors), len(warnings)))

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"rows": len(rows), "usable": ok_rows,
                       "errors": errors, "warnings": warnings}, f,
                      ensure_ascii=False, indent=1)
        print("report written to %s" % a.json)

    if errors or (a.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
