#!/usr/bin/env python3
"""Evaluate the running API on data/eval/samples.csv (synthetic, labelled).

One pass gives three systems from the same responses: hybrid (riskScore), rules only (ruleScore)
and LLM only (llmScore). A message counts as flagged when its score is >= 30 (Suspicious or
Likely Scam). Writes docs/eval-results.md and docs/eval-predictions.csv.

usage: python scripts/eval.py [--url http://localhost:8080]
(start the app with RATE_LIMIT_PER_MINUTE=1000 so the eval is not rate limited)
"""
import argparse
import csv
import json
import os
import statistics
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLAG_AT = 30
TYPE_LABELS = {
    "FAKE_KYC_ACCOUNT_BLOCK": "Fake KYC / account-block", "UPI_COLLECT_FRAUD": "UPI collect-request fraud",
    "FAKE_JOB_TASK": "Fake job / task scam", "LOTTERY_PRIZE": "Lottery / prize scam", "LOAN_APP": "Loan app scam",
    "ELECTRICITY_BILL": "Electricity-bill disconnection scam", "COURIER_CUSTOMS": "Courier / customs scam",
    "INVESTMENT_TRADING": "Investment / trading-group scam",
    "IMPERSONATION": "Impersonation (bank / police / digital arrest)", "PHISHING_LINK": "Phishing link",
    "OTHER": "Other", "NONE": "None"}


def post(url, text, channel):
    req = urllib.request.Request(url + "/api/v1/analyze", method="POST",
                                 data=json.dumps({"text": text, "channel": channel}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.loads(r.read())


def metrics(y_true, y_pred):
    tp = sum(t and p for t, p in zip(y_true, y_pred))
    tn = sum((not t) and (not p) for t, p in zip(y_true, y_pred))
    fp = sum((not t) and p for t, p in zip(y_true, y_pred))
    fn = sum(t and (not p) for t, p in zip(y_true, y_pred))
    n = len(y_true)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return dict(n=n, acc=(tp + tn) / n if n else 0, prec=prec, rec=rec, f1=f1, tp=tp, tn=tn, fp=fp, fn=fn)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8080")
    a = ap.parse_args()
    rows = list(csv.DictReader(open(os.path.join(ROOT, "data", "eval", "samples.csv"), encoding="utf-8")))
    preds = []
    for r in rows:
        t0 = time.time()
        d = post(a.url, r["text"], r["channel"])
        preds.append(dict(id=r["id"], label=r["label"], true_type=r["scam_type"], verdict=d["verdict"],
                          risk=d["riskScore"], rule=d["ruleScore"], llm=d["llmScore"], mode=d["mode"],
                          pred_type=d["scamType"], latency=time.time() - t0))
        print(f"{r['id']}: {d['verdict']:<11} risk={d['riskScore']:>3} rule={d['ruleScore']:>3} "
              f"llm={d['llmScore']} {d['mode']} | {d['scamType']}", flush=True)

    y = [p["label"] == "scam" for p in preds]
    systems = {"Hybrid (rules + RAG + LLM)": [p["risk"] >= FLAG_AT for p in preds],
               "Rules only": [p["rule"] >= FLAG_AT for p in preds]}
    hybrid_rows = [p for p in preds if p["llm"] is not None]
    if hybrid_rows:
        systems["LLM only"] = [(p["llm"] if p["llm"] is not None else p["rule"]) >= FLAG_AT for p in preds]
    scam_rows = [p for p in preds if p["label"] == "scam"]
    type_ok = sum(p["pred_type"] == TYPE_LABELS[p["true_type"]] for p in scam_rows)
    three = {(lab, v): 0 for lab in ("scam", "genuine") for v in ("Safe", "Suspicious", "Likely Scam")}
    for p in preds:
        three[(p["label"], p["verdict"])] += 1

    out = ["# Evaluation results", "",
           f"Dataset: `data/eval/samples.csv`: {len(preds)} synthetic messages "
           f"({sum(y)} scam, {len(y) - sum(y)} genuine). A message is flagged when its score is >= {FLAG_AT}.",
           f"LLM answered for {len(hybrid_rows)}/{len(preds)} messages (others fell back to rules). "
           f"Median latency {statistics.median(p['latency'] for p in preds):.1f} s per message "
           f"(local {preds[0] and 'Ollama'} model on a laptop GPU).", "",
           "| System | Accuracy | Precision | Recall | F1 | TP | FP | TN | FN |", "|---|---|---|---|---|---|---|---|---|"]
    for name, yp in systems.items():
        m = metrics(y, yp)
        out.append(f"| {name} | {m['acc']:.3f} | {m['prec']:.3f} | {m['rec']:.3f} | {m['f1']:.3f} | "
                   f"{m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} |")
    out += ["", f"Scam-type accuracy (hybrid, on the {len(scam_rows)} scam messages): "
                f"{type_ok}/{len(scam_rows)} = {type_ok / max(len(scam_rows), 1):.3f}", "",
            "Hybrid verdicts (rows = true label):", "",
            "| | Safe | Suspicious | Likely Scam |", "|---|---|---|---|"]
    for lab in ("scam", "genuine"):
        out.append(f"| {lab} | {three[(lab, 'Safe')]} | {three[(lab, 'Suspicious')]} | {three[(lab, 'Likely Scam')]} |")
    errs = [p for p, t, pr in zip(preds, y, systems["Hybrid (rules + RAG + LLM)"]) if t != pr]
    if errs:
        out += ["", "Hybrid errors:", ""] + [f"- `{p['id']}` ({p['label']}): {p['verdict']} (risk {p['risk']})" for p in errs]
    os.makedirs(os.path.join(ROOT, "docs"), exist_ok=True)
    open(os.path.join(ROOT, "docs", "eval-results.md"), "w", encoding="utf-8").write("\n".join(out) + "\n")
    with open(os.path.join(ROOT, "docs", "eval-predictions.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(preds[0]))
        w.writeheader()
        w.writerows(preds)
    print("\n".join(out))


if __name__ == "__main__":
    main()
