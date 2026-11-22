#!/usr/bin/env python3
"""Capture 1920x1080 screenshots of the running app (http://localhost:8080) for the demo video.
Drives the real UI in Microsoft Edge via Playwright; also stores each live API result as JSON.

usage: python docs/demo/capture.py <out_dir>
"""
import json
import os
import sys

from playwright.sync_api import sync_playwright

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
EXAMPLES = [("kyc", "Fake KYC SMS"), ("upi", "UPI collect request"), ("otp", "Genuine bank OTP"),
            ("arrest", "Digital arrest call")]

with sync_playwright() as p:
    b = p.chromium.launch(channel="msedge")
    page = b.new_page(viewport={"width": 1600, "height": 900}, device_scale_factor=1.2)
    results = {}
    page.on("response", lambda r: results.__setitem__("last", r.json()) if "/api/v1/analyze" in r.url else None)
    page.goto("http://localhost:8080/")
    page.wait_for_selector(".chip")
    page.screenshot(path=os.path.join(OUT, "home.png"))
    for key, label in EXAMPLES:
        page.evaluate("window.scrollTo(0,0)")
        page.get_by_role("button", name=label).click()
        page.wait_for_timeout(400)
        page.screenshot(path=os.path.join(OUT, f"{key}_0_input.png"))
        page.wait_for_function("document.getElementById('check').textContent === 'Check'", timeout=180000)
        page.wait_for_timeout(800)
        results[key] = results.pop("last")
        page.locator("#verdict").scroll_into_view_if_needed()
        page.evaluate("document.getElementById('verdict').scrollIntoView({block:'start'}); window.scrollBy(0,-20)")
        page.wait_for_timeout(300)
        page.screenshot(path=os.path.join(OUT, f"{key}_1_result.png"))
        page.evaluate("document.getElementById('actions').scrollIntoView({block:'center'})")
        page.wait_for_timeout(300)
        page.screenshot(path=os.path.join(OUT, f"{key}_2_actions.png"))
        if key == "upi":
            page.locator("details.why summary").click()
            page.evaluate("document.querySelector('details.why').scrollIntoView({block:'start'}); window.scrollBy(0,-20)")
            page.wait_for_timeout(300)
            page.screenshot(path=os.path.join(OUT, "upi_3_why.png"))
            page.locator("details.why summary").click()
    b.close()
json.dump(results, open(os.path.join(OUT, "results.json"), "w"), indent=1)
for k, v in results.items():
    print(k, v["verdict"], v["riskScore"], v["scamType"], v["mode"], "rule", v["ruleScore"], "llm", v["llmScore"],
          f"{v['latencyMs'] / 1000:.1f}s")
