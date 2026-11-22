#!/usr/bin/env python3
"""Assemble the demo video from screenshots of the live app (docs/demo/capture.py), cards drawn here, and
offline Windows speech synthesis for narration. Numbers on the eval card are read from docs/eval-results.md.

usage: python docs/demo/make_demo.py <shots_dir> <work_dir> <out.mp4>
"""
import os
import re
import subprocess
import sys
import wave

import imageio_ffmpeg
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FF = imageio_ffmpeg.get_ffmpeg_exe()
W, H, FPS = 1920, 1080, 30
BG, TEXT, MUTED, ACCENT, CARD = (246, 247, 249), (29, 35, 48), (93, 102, 119), (31, 79, 209), (255, 255, 255)
RED, GREEN = (179, 38, 30), (23, 114, 69)
FD = "C:/Windows/Fonts"


def f(name, size):
    return ImageFont.truetype(os.path.join(FD, name), size)


def tts(text, wav):
    open(wav + ".txt", "w", encoding="utf-8").write(text)
    ps = ("Add-Type -AssemblyName System.Speech; $s=New-Object System.Speech.Synthesis.SpeechSynthesizer; "
          "$s.SelectVoice('Microsoft David Desktop'); $s.Rate=0; "
          f"$s.SetOutputToWaveFile('{wav}'); $s.Speak([IO.File]::ReadAllText('{wav}.txt')); $s.Dispose()")
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True)
    with wave.open(wav) as w:
        return w.getnframes() / w.getframerate()


def card(path, title, lines, sub=None):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((140, 120), title, font=f("calibrib.ttf", 72), fill=TEXT)
    y = 230
    if sub:
        d.text((140, y), sub, font=f("calibri.ttf", 38), fill=MUTED)
        y += 90
    for ln in lines:
        if isinstance(ln, tuple):
            txt, col, size = ln
        else:
            txt, col, size = ln, TEXT, 36
        d.text((140, y), txt, font=f("calibri.ttf", size), fill=col)
        y += int(size * 1.6)
    img.save(path)


def architecture(path):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((140, 100), "How it works", font=f("calibrib.ttf", 72), fill=TEXT)
    boxes = {
        "msg": (110, 470, 410, 590, "Message", "SMS, WhatsApp, UPI, link"),
        "rules": (520, 300, 900, 420, "Rule engine", "~20 weighted signals + URL checks"),
        "rag": (520, 470, 900, 590, "Retrieval (pgvector)", "official I4C / DoT advisories"),
        "llm": (1040, 470, 1420, 590, "Local LLM, strict JSON", "qwen3.5:4b via Ollama"),
        "blend": (1040, 300, 1420, 420, "Blend 0.5 / 0.5", "falls back to rules-only"),
        "out": (1520, 385, 1800, 505, "Verdict", "flags, sources, actions"),
    }
    for k, (x0, y0, x1, y1, t, s) in boxes.items():
        fill = ACCENT if k in ("msg", "out") else CARD
        d.rounded_rectangle((x0, y0, x1, y1), radius=18, fill=fill, outline=(214, 219, 228), width=2)
        tc = CARD if fill == ACCENT else TEXT
        d.text(((x0 + x1) // 2, y0 + 38), t, font=f("calibrib.ttf", 32), fill=tc, anchor="mm")
        d.text(((x0 + x1) // 2, y0 + 82), s, font=f("calibri.ttf", 24), fill=CARD if fill == ACCENT else MUTED,
               anchor="mm")

    def arrow(a, b):
        d.line((a, b), fill=MUTED, width=4)
        import math
        ang = math.atan2(b[1] - a[1], b[0] - a[0])
        for s in (2.6, -2.6):
            d.line((b, (b[0] + 18 * math.cos(ang + s), b[1] + 18 * math.sin(ang + s))), fill=MUTED, width=4)
    arrow((410, 500), (520, 380))
    arrow((410, 530), (520, 530))
    arrow((710, 420), (710, 470))
    arrow((900, 530), (1040, 530))
    arrow((900, 360), (1040, 360))
    arrow((1230, 470), (1230, 420))
    arrow((1420, 360), (1520, 430))
    d.text((140, 720), "Java 21  \u2022  Spring Boot 4 + Spring AI  \u2022  PostgreSQL + pgvector  \u2022  Ollama "
           "(no API key, messages never leave the machine)", font=f("calibri.ttf", 30), fill=MUTED)
    d.text((140, 790), "Red-flag spans must exist in the message, and citations are excerpt numbers mapped to real "
           "URLs,", font=f("calibri.ttf", 30), fill=MUTED)
    d.text((140, 838), "so the model cannot invent a link.", font=f("calibri.ttf", 30), fill=MUTED)
    img.save(path)


def eval_card(path):
    md = open(os.path.join(ROOT, "docs", "eval-results.md"), encoding="utf-8").read()
    rows = re.findall(r"^\| (Hybrid[^|]*|Rules only|LLM only) \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \|", md, re.M)
    n = re.search(r"(\d+) synthetic messages \((\d+) scam, (\d+) genuine\)", md)
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.text((140, 100), "Evaluation", font=f("calibrib.ttf", 72), fill=TEXT)
    d.text((140, 205), f"{n.group(1)} synthetic labelled messages ({n.group(2)} scam, {n.group(3)} genuine), "
           "flagged at risk \u2265 30", font=f("calibri.ttf", 36), fill=MUTED)
    cols = [140, 900, 1130, 1360, 1590]
    for x, h in zip(cols, ["System", "Accuracy", "Precision", "Recall", "F1"]):
        d.text((x, 320), h, font=f("calibrib.ttf", 36), fill=TEXT)
    for i, r in enumerate(rows):
        y = 400 + i * 85
        d.rounded_rectangle((120, y - 15, 1800, y + 60), radius=12, fill=CARD)
        for x, v in zip(cols, r):
            d.text((x, y), v.strip(), font=f("calibri.ttf", 38), fill=TEXT)
    d.text((140, 700), "Honest caveat: the set is small, synthetic and written alongside the rules, so it is easier",
           font=f("calibri.ttf", 34), fill=RED)
    d.text((140, 750), "than real traffic. It shows the pipeline works end to end, not real-world accuracy.",
           font=f("calibri.ttf", 34), fill=RED)
    img.save(path)
    return rows


def scene(img, wav, dur, out):
    subprocess.run([FF, "-y", "-v", "error", "-loop", "1", "-framerate", str(FPS), "-t", f"{dur:.2f}", "-i", img,
                    "-i", wav, "-filter_complex",
                    f"[0:v]scale={W}:{H},format=yuv420p[v];[1:a]apad,atrim=0:{dur:.2f},aresample=48000[a]",
                    "-map", "[v]", "-map", "[a]", "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
                    "-r", str(FPS), "-c:a", "aac", "-b:a", "160k", "-ac", "2", out], check=True)


def main():
    shots, work, out = sys.argv[1:4]
    os.makedirs(work, exist_ok=True)
    title = os.path.join(work, "title.png")
    card(title, "ScamShield India: is this a scam?",
         [("Paste a suspicious SMS, WhatsApp message, email, UPI request or link.", TEXT, 40),
          ("Get a verdict, the red flags, the reasons with official sources, and what to do now.", TEXT, 40),
          ("", TEXT, 20), ("Arthaton 2026  \u2022  AI for finance: scam and fraud detection", MUTED, 34)])
    arch = os.path.join(work, "arch.png")
    architecture(arch)
    ev = os.path.join(work, "eval.png")
    rows = eval_card(ev)
    hyb = rows[0]
    rules = rows[1]
    close = os.path.join(work, "close.png")
    card(close, "Thank you",
         [("Code, data sources, evaluation and setup: github.com/Ayush0612005/scamshield-india", TEXT, 38),
          ("", TEXT, 20),
          ("Lost money to a scam? Call the National Cybercrime Helpline 1930", RED, 40),
          ("or report at cybercrime.gov.in. Report fraud messages on Sanchar Saathi (Chakshu).", RED, 40)])

    S = lambda n: os.path.join(shots, n)  # noqa: E731
    plan = [
        (title, "This is ScamShield India. Fraud messages in India look official: a bank asking you to update KYC, "
                "a buyer asking you to approve a UPI request, a police officer on a video call. ScamShield answers one "
                "question for anyone who receives one: is this a scam?"),
        (S("home.png"), "You paste the message, choose where it came from, and press check. These example chips are "
                        "synthetic messages, so no real names or numbers are used."),
        (S("kyc_1_result.png"), "First, a fake KYC text. The verdict is Likely Scam, with a risk of ninety-eight. "
                                "The red flags are highlighted inside the message itself: the blocking threat, the "
                                "urgency, a lookalike S B I link on a dot X Y Z domain, and a personal mobile number. "
                                "Below that is a plain-English explanation, and a list of what to do now."),
        (S("upi_1_result.png"), "Next, a classic marketplace trick. I have paid you, now enter your UPI PIN to receive "
                                "the money. A UPI PIN is only ever needed to pay, never to receive, and ScamShield "
                                "flags exactly that sentence."),
        (S("upi_3_why.png"), "Every verdict is explainable. The rule engine gives points for each signal it found. "
                             "The local language model gives its own score. The final risk is the average of the two, "
                             "and if the model is slow or fails, you still get the rules-only answer."),
        (S("otp_1_result.png"), "Just as important is not crying wolf. This is a normal bank O T P message that says "
                                "do not share. The verdict is Safe, with a risk of three."),
        (S("arrest_1_result.png"), "Finally, a digital arrest call. ScamShield flags the fake officer, the seized "
                                   "parcel, and the instruction to stay on the video call, and it cites the official "
                                   "I 4 C advisory, which says there is no such thing as a digital arrest in Indian "
                                   "law."),
        (arch, "Under the hood: a Java and Spring Boot backend, a rule engine, retrieval over official advisories from "
               "I 4 C and the Department of Telecommunications, stored in Postgres with p g vector, and Qwen three "
               "point five running locally through Ollama with Spring AI. No API key is needed, and no message "
               "leaves the machine."),
        (ev, f"On sixty synthetic labelled messages, the hybrid system scored an accuracy of {hyb[1].strip()}, and "
             f"the rules alone scored {rules[1].strip()}. The set is small and synthetic, so these numbers show that "
             "the pipeline works end to end. They are not a claim about real-world accuracy."),
        (close, "If you have lost money to a scam, call the national cybercrime helpline, nineteen thirty, or report "
                "it at cybercrime dot gov dot in. The code is on GitHub. Thank you."),
    ]
    scenes = []
    for i, (img, text) in enumerate(plan):
        wav = os.path.join(work, f"n{i}.wav")
        dur = tts(text, wav) + 0.8
        mp4 = os.path.join(work, f"s{i}.mp4")
        scene(img, wav, dur, mp4)
        scenes.append(mp4)
        print(f"scene {i}: {dur:.1f}s")
    lst = os.path.join(work, "list.txt")
    open(lst, "w").writelines(f"file '{s.replace(os.sep, '/')}'\n" for s in scenes)
    subprocess.run([FF, "-y", "-v", "error", "-f", "concat", "-safe", "0", "-i", lst, "-c", "copy",
                    "-movflags", "+faststart", out], check=True)
    print("wrote", out)


if __name__ == "__main__":
    main()
