package io.scamshield.service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.scamshield.api.Dtos.AnalyzeResponse;
import io.scamshield.api.Dtos.Citation;
import io.scamshield.api.Dtos.RedFlag;
import io.scamshield.api.Dtos.RuleSignal;
import io.scamshield.llm.LlmAnalyzer;
import io.scamshield.llm.LlmVerdict;
import io.scamshield.rag.AdvisoryStore;
import io.scamshield.rag.AdvisoryStore.Advisory;
import io.scamshield.rules.RuleEngine;
import io.scamshield.rules.RuleResult;
import io.scamshield.rules.ScamType;
import io.scamshield.rules.Signal;

/** Rules -> retrieval -> LLM -> blended, explainable verdict. Falls back to rules-only on any LLM failure. */
@Service
public class AnalysisService {

    /** Weight of the rule score in the blend; the LLM gets the rest. */
    static final double RULE_WEIGHT = 0.5;
    static final int SUSPICIOUS_AT = 30;
    static final int SCAM_AT = 60;

    private final RuleEngine rules;
    private final AdvisoryStore advisories;
    private final LlmAnalyzer llm;
    private final String model;

    public AnalysisService(RuleEngine rules, AdvisoryStore advisories, LlmAnalyzer llm,
                           @Value("${spring.ai.ollama.chat.model:unknown}") String model) {
        this.rules = rules;
        this.advisories = advisories;
        this.llm = llm;
        this.model = model;
    }

    public AnalyzeResponse analyze(String text, String channel) {
        long t0 = System.currentTimeMillis();
        RuleResult rr = rules.analyze(text);
        List<Advisory> docs = retrieve(text, rr);
        Optional<LlmVerdict> lv = llm.analyze(text, channel, rr, docs);

        int score = lv.map(v -> blend(rr.score(), v.riskScore())).orElse(rr.score());
        String verdict = verdictFor(score);
        ScamType type = chooseType(score, rr, lv.orElse(null));

        List<RedFlag> flags = new ArrayList<>();
        for (Signal s : rr.signals()) {
            if (s.weight() > 0 && s.start() >= 0) {
                flags.add(new RedFlag(s.start(), s.end(), text.substring(s.start(), s.end()), s.reason(), "rule"));
            }
        }
        lv.ifPresent(v -> v.redFlags().forEach(f -> {
            boolean overlaps = flags.stream().anyMatch(x -> x.start() < f.end() && f.start() < x.end());
            if (!overlaps) {
                flags.add(new RedFlag(f.start(), f.end(), f.textSpan(), f.reason(), "ai"));
            }
        }));
        flags.sort(Comparator.comparingInt(RedFlag::start));

        String explanation = lv.map(LlmVerdict::explanation).orElseGet(() -> rulesExplanation(rr, verdict));
        List<Citation> citations = citations(docs, lv.orElse(null), score);
        List<String> actions = actions(score, lv.orElse(null));
        List<RuleSignal> signals = rr.signals().stream()
                .map(s -> new RuleSignal(s.id(), s.reason(), s.weight(), s.start() >= 0 ? text.substring(s.start(), s.end()) : ""))
                .toList();

        return new AnalyzeResponse(verdict, score, type.label(), lv.isPresent() ? "hybrid" : "rules-only",
                rr.score(), lv.map(LlmVerdict::riskScore).orElse(null), lv.map(LlmVerdict::verdict).orElse(null),
                lv.isPresent() ? model : null, flags, explanation, citations, actions, signals,
                System.currentTimeMillis() - t0);
    }

    static int blend(int ruleScore, int llmScore) {
        return (int) Math.round(RULE_WEIGHT * ruleScore + (1 - RULE_WEIGHT) * llmScore);
    }

    static String verdictFor(int score) {
        return score >= SCAM_AT ? "Likely Scam" : score >= SUSPICIOUS_AT ? "Suspicious" : "Safe";
    }

    private List<Advisory> retrieve(String text, RuleResult rr) {
        try {
            String q = rr.scamType() == ScamType.NONE ? text : rr.scamType().label() + ". " + text;
            return advisories.search(q);
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    private static ScamType chooseType(int score, RuleResult rr, LlmVerdict lv) {
        if (score < SUSPICIOUS_AT) {
            return ScamType.NONE;
        }
        if (lv != null && lv.scamType() != ScamType.NONE && lv.scamType() != ScamType.OTHER) {
            return lv.scamType();
        }
        return rr.scamType() == ScamType.NONE ? ScamType.OTHER : rr.scamType();
    }

    private static String rulesExplanation(RuleResult rr, String verdict) {
        List<String> reasons = rr.signals().stream().filter(s -> s.weight() > 0)
                .sorted(Comparator.comparingInt(Signal::weight).reversed())
                .map(Signal::reason).distinct().limit(3).toList();
        if (reasons.isEmpty()) {
            return "No common scam patterns were found in this message. Still, never share an OTP, PIN or password, "
                    + "and verify any request for money through the official app or helpline.";
        }
        return verdict + ": " + String.join(" ", reasons);
    }

    private static List<Citation> citations(List<Advisory> docs, LlmVerdict lv, int score) {
        Map<String, Citation> out = new LinkedHashMap<>();
        List<Integer> idx = lv != null && !lv.citations().isEmpty() ? lv.citations()
                : score >= SUSPICIOUS_AT ? List.of(1, 2) : List.of();
        for (int i : idx) {
            if (i >= 1 && i <= docs.size()) {
                Advisory a = docs.get(i - 1);
                out.putIfAbsent(a.url(), new Citation(a.title(), a.url(), a.publisher(), a.date()));
            }
        }
        return List.copyOf(out.values());
    }

    private static List<String> actions(int score, LlmVerdict lv) {
        Set<String> out = new LinkedHashSet<>();
        if (score >= SUSPICIOUS_AT) {
            out.add("Do not share any OTP, UPI PIN, card CVV or password, and do not approve any UPI request.");
            out.add("Do not click the link or call the number in the message. Use your bank's official app or the number on your card.");
        }
        if (lv != null) {
            lv.actions().stream().limit(3).forEach(out::add);
        }
        if (score >= SUSPICIOUS_AT) {
            out.add("Report the message on Sanchar Saathi (Chakshu) and block the sender.");
            out.add("If money was taken, call the National Cybercrime Helpline 1930 immediately and report at cybercrime.gov.in.");
        } else {
            out.add("Looks normal, but never share an OTP or PIN with anyone, even if they claim to be from your bank.");
        }
        return List.copyOf(out);
    }
}
