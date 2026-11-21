package io.scamshield.llm;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import io.scamshield.rules.ScamType;

class LlmAnalyzerParseTest {

    @Test
    void parsesValidJsonAndDropsInventedSpansAndCitations() {
        String text = "Pay Rs 500 fee to get the job";
        String raw = "<think>x</think>{\"verdict\":\"Likely Scam\",\"risk_score\":88,\"scam_type\":\"FAKE_JOB_TASK\","
                + "\"red_flags\":[{\"text_span\":\"rs 500 fee\",\"reason\":\"upfront fee\"},{\"text_span\":\"not in text\",\"reason\":\"x\"}],"
                + "\"explanation\":\"Upfront fee for a job.\",\"citations\":[2,9],\"actions\":[\"Ignore it\"]}";
        LlmVerdict v = LlmAnalyzer.parse(raw, text, 3).orElseThrow();
        assertThat(v.riskScore()).isEqualTo(88);
        assertThat(v.scamType()).isEqualTo(ScamType.FAKE_JOB_TASK);
        assertThat(v.redFlags()).hasSize(1);
        assertThat(v.redFlags().get(0).textSpan()).isEqualTo("Rs 500 fee");
        assertThat(v.citations()).containsExactly(2);
    }

    @Test
    void rejectsInvalidOutput() {
        assertThat(LlmAnalyzer.parse("not json", "t", 1)).isEmpty();
        assertThat(LlmAnalyzer.parse("{\"verdict\":\"Maybe\",\"risk_score\":5,\"explanation\":\"x\"}", "t", 1)).isEmpty();
        assertThat(LlmAnalyzer.parse("{\"verdict\":\"Safe\",\"risk_score\":500,\"explanation\":\"x\"}", "t", 1)).isEmpty();
    }

    @Test
    void safeVerdictForcesNoneType() {
        LlmVerdict v = LlmAnalyzer.parse("{\"verdict\":\"Safe\",\"risk_score\":4,\"scam_type\":\"PHISHING_LINK\",\"explanation\":\"ok\"}", "t", 0).orElseThrow();
        assertThat(v.scamType()).isEqualTo(ScamType.NONE);
    }
}
