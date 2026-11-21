# Evaluation results

Dataset: `data/eval/samples.csv`: 60 synthetic messages (36 scam, 24 genuine). A message is flagged when its score is >= 30.
LLM answered for 60/60 messages (others fell back to rules). Median latency 6.5 s per message (local Ollama model on a laptop GPU).

| System | Accuracy | Precision | Recall | F1 | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| Hybrid (rules + RAG + LLM) | 1.000 | 1.000 | 1.000 | 1.000 | 36 | 0 | 24 | 0 |
| Rules only | 0.967 | 1.000 | 0.944 | 0.971 | 34 | 0 | 24 | 2 |
| LLM only | 1.000 | 1.000 | 1.000 | 1.000 | 36 | 0 | 24 | 0 |

Scam-type accuracy (hybrid, on the 36 scam messages): 34/36 = 0.944

Hybrid verdicts (rows = true label):

| | Safe | Suspicious | Likely Scam |
|---|---|---|---|
| scam | 0 | 5 | 31 |
| genuine | 24 | 0 | 0 |
