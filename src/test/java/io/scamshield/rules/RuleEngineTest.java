package io.scamshield.rules;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class RuleEngineTest {

    private final RuleEngine engine = new RuleEngine();

    private static boolean has(RuleResult r, String id) {
        return r.signals().stream().anyMatch(s -> s.id().equals(id));
    }

    @Test
    void fakeKycSmsScoresHigh() {
        RuleResult r = engine.analyze("Dear customer, your SBI account will be blocked today. Update your KYC immediately at http://sbi-kyc-update.xyz/login");
        assertThat(r.score()).isGreaterThanOrEqualTo(60);
        assertThat(has(r, "ACCOUNT_BLOCK")).isTrue();
        assertThat(has(r, "SUSPICIOUS_LINK")).isTrue();
        assertThat(r.scamType()).isIn(ScamType.FAKE_KYC_ACCOUNT_BLOCK, ScamType.PHISHING_LINK);
    }

    @Test
    void enteringPinToReceiveMoneyIsFlagged() {
        RuleResult r = engine.analyze("You have received a cashback of Rs 2,000. To receive the amount please enter your UPI PIN in the request.");
        assertThat(has(r, "PIN_TO_RECEIVE")).isTrue();
        assertThat(r.score()).isGreaterThanOrEqualTo(60);
        assertThat(r.scamType()).isEqualTo(ScamType.UPI_COLLECT_FRAUD);
    }

    @Test
    void genuineOtpMessageIsSafe() {
        RuleResult r = engine.analyze("123456 is your OTP for login to net banking. Valid for 5 minutes. Do not share this OTP with anyone. - XYZ Bank");
        assertThat(r.score()).isLessThan(25);
        assertThat(has(r, "OTP_REQUEST")).isFalse();
        assertThat(r.scamType()).isEqualTo(ScamType.NONE);
    }

    @Test
    void doNotShareNoticeDoesNotCancelAnOtpRequest() {
        RuleResult r = engine.analyze("Do not share OTP with others. But to verify your account please share the OTP with our executive now.");
        assertThat(has(r, "OTP_REQUEST")).isTrue();
        assertThat(r.signals().stream().filter(s -> s.id().equals("GENUINE_OTP_NOTICE")).allMatch(s -> s.weight() == 0)).isTrue();
        assertThat(r.score()).isGreaterThanOrEqualTo(40);
    }

    @Test
    void digitalArrestIsImpersonation() {
        RuleResult r = engine.analyze("This is CBI. A parcel in your name with drugs was seized by customs. You are under digital arrest, stay on the video call.");
        assertThat(r.scamType()).isEqualTo(ScamType.IMPERSONATION);
        assertThat(r.score()).isGreaterThanOrEqualTo(60);
    }

    @Test
    void urlFeatures() {
        assertThat(RuleEngine.hostOf("https://www.example.com/path?x=1")).isEqualTo("example.com");
        assertThat(engine.analyze("check http://192.168.10.5/pay").signals())
                .anyMatch(s -> s.reason().contains("raw IP"));
        assertThat(engine.analyze("see bit.ly/abc123").signals())
                .anyMatch(s -> s.reason().contains("shortener"));
        assertThat(engine.analyze("Visit https://www.onlinesbi.sbi for details").score()).isZero();
    }

    @Test
    void spansPointIntoTheText() {
        String text = "Earn Rs 5000 per day by liking YouTube videos. Part time job, WhatsApp 9876543210";
        RuleResult r = engine.analyze(text);
        assertThat(r.scamType()).isEqualTo(ScamType.FAKE_JOB_TASK);
        r.signals().forEach(s -> {
            assertThat(s.start()).isBetween(0, text.length());
            assertThat(s.end()).isBetween(s.start(), text.length());
        });
    }

    @Test
    void ordinaryMessageIsSafe() {
        RuleResult r = engine.analyze("Your order of 2 items has been shipped and will be delivered on Friday. Track it in the app.");
        assertThat(r.score()).isLessThan(25);
    }
}
