package io.scamshield.llm;

import java.util.List;

import io.scamshield.rules.ScamType;

/** Validated LLM output. {@code citations} are 1-based indexes into the advisories that were retrieved. */
public record LlmVerdict(String verdict, int riskScore, ScamType scamType, List<Flag> redFlags, String explanation,
                         List<Integer> citations, List<String> actions) {

    public record Flag(String textSpan, String reason, int start, int end) {
    }
}
