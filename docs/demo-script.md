# Demo video script (target 3:30, hard limit under 5:00)

Record the screen at 1080p with the app at http://localhost:8080 (Ollama + `docker compose up -d db` running).
Before recording, click one example once so the model is warm. Upload to YouTube as **Unlisted**.

| Time | Screen | Say |
|---|---|---|
| 0:00-0:25 | Title slide or the empty app | "Every day people in India get messages like 'your account will be blocked, update KYC now'. Victims who lose money are told to call 1930 or report on cybercrime.gov.in, but most people don't know a message is a scam until it's too late. ScamShield answers one question: is this a scam?" |
| 0:25-1:10 | Click **Fake KYC SMS**, wait for result | "Here's a fake KYC SMS. Verdict: Likely Scam, fake KYC type. The red flags are highlighted inside the message: the blocking threat, the urgency, a lookalike SBI link on a .xyz domain, and a personal mobile number. The explanation is grounded in official advisories, and the sources are linked." |
| 1:10-1:50 | Click **UPI collect request** | "A classic marketplace scam: 'I've paid you, enter your UPI PIN to receive the money.' A UPI PIN is only ever needed to pay. ScamShield flags exactly that sentence and tells you what to do: don't approve, don't enter the PIN, report on Chakshu, call 1930 if money was taken." |
| 1:50-2:20 | Click **Genuine bank OTP** | "It's just as important not to cry wolf. This is a real-style bank OTP message that says 'do not share'. Verdict: Safe. No false alarm." |
| 2:20-2:50 | Expand **Why this verdict** on the UPI example | "Every verdict is explainable. A deterministic rule engine scores about 20 signals, and here are the points each one gave. A local LLM gives its own score. The final score blends the two, and if the model is slow or fails, you still get the rules-only answer." |
| 2:50-3:15 | Show architecture diagram in the README | "Under the hood: Java 21 and Spring Boot, a rule engine, RAG over official I4C and Department of Telecom advisories in PostgreSQL with pgvector, and Qwen 3.5 running locally through Ollama via Spring AI. No API key, and no message leaves the machine." |
| 3:15-3:30 | docs/eval-results.md | "On 60 synthetic labelled messages, here are the measured accuracy, precision and recall for the hybrid system versus rules alone. Code and data are on GitHub. Thanks!" |

Read the numbers off `docs/eval-results.md` exactly. Do not round them up.
