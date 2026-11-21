package io.scamshield.rules;

/**
 * One red flag (or, with a negative weight, a reassuring sign) found in the message.
 *
 * @param id       stable rule id, e.g. {@code OTP_REQUEST}
 * @param reason   plain-language explanation shown to the user
 * @param weight   contribution to the 0-100 rule score
 * @param start    start offset of the matched text in the input (-1 if not tied to a span)
 * @param end      end offset (exclusive)
 * @param scamType scam category this signal points to (null for neutral signals)
 */
public record Signal(String id, String reason, int weight, int start, int end, ScamType scamType) {
}
