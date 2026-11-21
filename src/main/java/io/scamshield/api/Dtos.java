package io.scamshield.api;

import java.util.List;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class Dtos {

    private Dtos() {
    }

    public record AnalyzeRequest(
            @NotBlank(message = "text must not be empty")
            @Size(max = 5000, message = "text must be at most 5000 characters") String text,
            @Size(max = 30) String channel) {
    }

    public record RedFlag(int start, int end, String text, String reason, String source) {
    }

    public record Citation(String title, String url, String publisher, String date) {
    }

    public record RuleSignal(String id, String reason, int weight, String text) {
    }

    public record AnalyzeResponse(
            String verdict,
            int riskScore,
            String scamType,
            String mode,
            int ruleScore,
            Integer llmScore,
            String llmVerdict,
            String model,
            List<RedFlag> redFlags,
            String explanation,
            List<Citation> citations,
            List<String> actions,
            List<RuleSignal> ruleSignals,
            long latencyMs) {
    }

    public record Example(String id, String title, String channel, String text) {
    }

    public record ErrorResponse(int status, String error, String message) {
    }
}
