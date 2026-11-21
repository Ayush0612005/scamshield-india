package io.scamshield.llm;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.scamshield.rag.AdvisoryStore.Advisory;
import io.scamshield.rules.RuleResult;
import io.scamshield.rules.ScamType;
import io.scamshield.rules.Signal;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Asks the LLM for a strict-JSON verdict grounded in the rule signals and retrieved advisories,
 * then validates every field. Any failure (timeout, bad JSON, invalid values) returns empty so the
 * caller falls back to the rule engine.
 */
@Service
public class LlmAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(LlmAnalyzer.class);
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Set<String> VERDICTS = Set.of("Safe", "Suspicious", "Likely Scam");

    static final String SYSTEM = """
            You are a fraud analyst helping people in India decide whether a message they received is a scam.
            You get the message, red-flag signals found by a rule engine, and numbered excerpts from official
            advisories. Judge the message yourself; the rule signals can be incomplete or wrong.
            Genuine messages exist: bank OTP messages that say "do not share", delivery updates, real
            transaction alerts. Do not call something a scam only because it mentions a bank or an OTP.

            Reply with ONE JSON object and nothing else, with exactly these keys:
            {
              "verdict": "Safe" | "Suspicious" | "Likely Scam",
              "risk_score": integer 0-100 (0 = certainly genuine, 100 = certainly a scam),
              "scam_type": one of %s,
              "red_flags": [{"text_span": exact substring copied from the message, "reason": short reason}],
              "explanation": 2-4 plain-English sentences a non-technical person understands,
              "citations": [numbers of the advisory excerpts that support your explanation, e.g. 1, 3],
              "actions": [3-5 short concrete steps for the user]
            }
            Use scam_type "NONE" when the verdict is Safe. Cite only excerpt numbers that are listed.
            """;

    private final ChatClient chat;
    private final long timeoutSeconds;
    private final boolean enabled;

    public LlmAnalyzer(ChatClient.Builder builder, @Value("${scamshield.llm.timeout-seconds:45}") long timeoutSeconds,
                       @Value("${scamshield.llm.enabled:true}") boolean enabled) {
        this.chat = builder.build();
        this.timeoutSeconds = timeoutSeconds;
        this.enabled = enabled;
    }

    public Optional<LlmVerdict> analyze(String text, String channel, RuleResult rules, List<Advisory> advisories) {
        if (!enabled) {
            return Optional.empty();
        }
        String types = Arrays.stream(ScamType.values()).map(Enum::name).collect(Collectors.joining(", "));
        String user = buildUserPrompt(text, channel, rules, advisories);
        try {
            String raw = CompletableFuture.supplyAsync(() -> chat.prompt()
                            .system(SYSTEM.formatted(types))
                            .user(user)
                            .call()
                            .content())
                    .get(timeoutSeconds, TimeUnit.SECONDS);
            Optional<LlmVerdict> v = parse(raw, text, advisories.size());
            if (v.isEmpty()) {
                log.warn("LLM output rejected by validation: {}", raw == null ? "null" : raw.substring(0, Math.min(300, raw.length())));
            }
            return v;
        } catch (Exception e) {
            log.warn("LLM call failed, falling back to rules: {}", e.toString());
            return Optional.empty();
        }
    }

    static String buildUserPrompt(String text, String channel, RuleResult rules, List<Advisory> advisories) {
        StringBuilder sb = new StringBuilder();
        sb.append("Channel: ").append(channel == null || channel.isBlank() ? "unknown" : channel).append("\n\n");
        sb.append("Message:\n\"\"\"\n").append(text).append("\n\"\"\"\n\n");
        sb.append("Rule engine score: ").append(rules.score()).append("/100\nRule signals:\n");
        List<Signal> pos = rules.signals().stream().filter(s -> s.weight() != 0).toList();
        if (pos.isEmpty()) {
            sb.append("- none\n");
        }
        for (Signal s : pos) {
            sb.append("- ").append(s.id()).append(" (").append(s.weight()).append("): ").append(s.reason());
            if (s.start() >= 0) {
                sb.append(" [\"").append(text, s.start(), s.end()).append("\"]");
            }
            sb.append('\n');
        }
        sb.append("\nAdvisory excerpts:\n");
        for (int i = 0; i < advisories.size(); i++) {
            Advisory a = advisories.get(i);
            sb.append('[').append(i + 1).append("] ").append(a.title()).append(" (").append(a.publisher()).append(")\n")
                    .append(a.text()).append("\n\n");
        }
        if (advisories.isEmpty()) {
            sb.append("(none available)\n");
        }
        return sb.toString();
    }

    static Optional<LlmVerdict> parse(String raw, String text, int nAdvisories) {
        if (raw == null) {
            return Optional.empty();
        }
        String s = raw.replaceAll("(?s)<think>.*?</think>", "").strip();
        int a = s.indexOf('{');
        int b = s.lastIndexOf('}');
        if (a < 0 || b <= a) {
            return Optional.empty();
        }
        JsonNode n;
        try {
            n = JSON.readTree(s.substring(a, b + 1));
        } catch (Exception e) {
            return Optional.empty();
        }
        String verdict = normaliseVerdict(n.path("verdict").asString(""));
        if (verdict == null || !n.path("risk_score").isNumber()) {
            return Optional.empty();
        }
        int risk = (int) Math.round(n.path("risk_score").asDouble());
        if (risk < 0 || risk > 100) {
            return Optional.empty();
        }
        String explanation = n.path("explanation").asString("").strip();
        if (explanation.isEmpty()) {
            return Optional.empty();
        }
        ScamType type = parseType(n.path("scam_type").asString(""));
        if ("Safe".equals(verdict)) {
            type = ScamType.NONE;
        } else if (type == ScamType.NONE) {
            type = ScamType.OTHER;
        }

        List<LlmVerdict.Flag> flags = new ArrayList<>();
        String lower = text.toLowerCase(Locale.ROOT);
        for (JsonNode f : n.path("red_flags")) {
            String span = f.path("text_span").asString("").strip();
            String reason = f.path("reason").asString("").strip();
            if (span.isEmpty() || reason.isEmpty()) {
                continue;
            }
            int at = lower.indexOf(span.toLowerCase(Locale.ROOT));
            if (at >= 0) {  // keep only spans that really occur in the message
                flags.add(new LlmVerdict.Flag(text.substring(at, at + span.length()), reason, at, at + span.length()));
            }
        }
        List<Integer> cites = new ArrayList<>();
        for (JsonNode c : n.path("citations")) {
            int k = c.isNumber() ? c.asInt() : parseIntOr(c.asString(""), -1);
            if (k >= 1 && k <= nAdvisories && !cites.contains(k)) {
                cites.add(k);
            }
        }
        List<String> actions = new ArrayList<>();
        for (JsonNode x : n.path("actions")) {
            String t = x.asString("").strip();
            if (!t.isEmpty() && actions.size() < 6) {
                actions.add(t);
            }
        }
        return Optional.of(new LlmVerdict(verdict, risk, type, flags, explanation, cites, actions));
    }

    private static int parseIntOr(String s, int d) {
        try {
            return Integer.parseInt(s.replaceAll("[^0-9]", ""));
        } catch (NumberFormatException e) {
            return d;
        }
    }

    private static String normaliseVerdict(String v) {
        String t = v.strip().toLowerCase(Locale.ROOT).replace('_', ' ');
        for (String ok : VERDICTS) {
            if (ok.toLowerCase(Locale.ROOT).equals(t)) {
                return ok;
            }
        }
        if (t.equals("scam") || t.equals("likely scam")) {
            return "Likely Scam";
        }
        return null;
    }

    private static ScamType parseType(String s) {
        String t = s.strip().toUpperCase(Locale.ROOT).replaceAll("[^A-Z]+", "_").replaceAll("^_|_$", "");
        for (ScamType st : ScamType.values()) {
            if (st.name().equals(t) || st.label().toUpperCase(Locale.ROOT).replaceAll("[^A-Z]+", "_").replaceAll("^_|_$", "").equals(t)) {
                return st;
            }
        }
        return t.isEmpty() ? ScamType.NONE : ScamType.OTHER;
    }
}
