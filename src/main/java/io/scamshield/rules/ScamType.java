package io.scamshield.rules;

public enum ScamType {
    FAKE_KYC_ACCOUNT_BLOCK("Fake KYC / account-block"),
    UPI_COLLECT_FRAUD("UPI collect-request fraud"),
    FAKE_JOB_TASK("Fake job / task scam"),
    LOTTERY_PRIZE("Lottery / prize scam"),
    LOAN_APP("Loan app scam"),
    ELECTRICITY_BILL("Electricity-bill disconnection scam"),
    COURIER_CUSTOMS("Courier / customs scam"),
    INVESTMENT_TRADING("Investment / trading-group scam"),
    IMPERSONATION("Impersonation (bank / police / digital arrest)"),
    PHISHING_LINK("Phishing link"),
    OTHER("Other"),
    NONE("None");

    private final String label;

    ScamType(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
