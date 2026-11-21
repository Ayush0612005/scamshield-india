package io.scamshield.rules;

import java.util.List;

/** Output of the rule engine: a 0-100 score, the dominant scam type and every signal found. */
public record RuleResult(int score, ScamType scamType, List<Signal> signals) {
}
