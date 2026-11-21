package io.scamshield.rules;

import java.net.IDN;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

/**
 * Deterministic, explainable scam signals. Each rule fires at most once (its weight counts once),
 * but every matching span is reported so the UI can highlight all of them.
 */
@Component
public class RuleEngine {

    private record Rule(String id, Pattern pattern, int weight, String reason, ScamType type) {
    }

    private static Pattern p(String regex) {
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
    }

    private static final List<Rule> RULES = List.of(
            new Rule("OTP_REQUEST",
                    p("(?<!\\bnot |n't |\\bnever )\\b(share|send|tell|give|provide|forward|read out|confirm)\\b[^.\\n]{0,40}\\b(otp|one[ -]?time[ -]?password|verification code)\\b"
                            + "|\\b(otp|verification code)\\b[^.\\n]{0,30}\\b(share|send|tell|reply|forward)\\b(?![^.\\n]{0,20}\\b(anyone|any one|no one)\\b)"),
                    40, "Asks you to share an OTP. Banks and genuine services never ask for your OTP.",
                    ScamType.FAKE_KYC_ACCOUNT_BLOCK),
            new Rule("PIN_REQUEST",
                    p("(?<!\\bnot |n't |\\bnever )\\b(enter|share|send|provide|type|tell)\\b[^.\\n]{0,30}\\b(upi pin|mpin|atm pin|card pin|cvv|pin)\\b"),
                    40, "Asks for your PIN or CVV. Never share or enter these on request.",
                    ScamType.UPI_COLLECT_FRAUD),
            new Rule("PIN_TO_RECEIVE",
                    p("\\b(receive|get|claim|credit(ed)?)\\b[^.\\n]{0,60}\\b(enter|scan|approve)\\b[^.\\n]{0,30}\\b(pin|qr)\\b"
                            + "|\\b(enter|scan)\\b[^.\\n]{0,30}\\b(pin|qr)\\b[^.\\n]{0,40}\\b(receive|get|claim)\\b"),
                    45, "Says you must enter a PIN or scan a QR code to RECEIVE money. A UPI PIN is only needed to pay, never to receive.",
                    ScamType.UPI_COLLECT_FRAUD),
            new Rule("UPI_COLLECT",
                    p("\\b(collect request|payment request|request money|money request|approve the (request|payment)|accept the (request|payment))\\b"),
                    25, "Mentions a UPI collect or payment request. Approving one sends money out of your account.",
                    ScamType.UPI_COLLECT_FRAUD),
            new Rule("URGENCY",
                    p("\\b(urgent(ly)?|immediately|within \\d+ ?(hours?|hrs?|minutes?|mins?)|today itself|tonight|last (warning|chance|reminder)|act now|final notice|expires? today)\\b"),
                    15, "Creates urgency so you act before thinking.", null),
            new Rule("ACCOUNT_BLOCK",
                    p("\\b(account|card|sim|wallet|kyc|pan|aadhaa?r)\\b[^.\\n]{0,40}\\b(block(ed)?|suspend(ed)?|deactivat(ed|e)|freez(e|ed)|clos(ed|e)|expir(ed|e)|pending|not updated)\\b"
                            + "|\\b(update|complete|verify)\\b[^.\\n]{0,15}\\b(kyc|pan|aadhaa?r)\\b"),
                    25, "Threatens that your account, card, KYC or SIM will be blocked or needs updating via a message.",
                    ScamType.FAKE_KYC_ACCOUNT_BLOCK),
            new Rule("PRIZE",
                    p("\\b(lottery|lucky draw|you (have )?won|winner|prize|jackpot|kbc|gift voucher|cash ?back reward|reward points? (expir|redeem))"),
                    25, "Promises a prize, lottery or reward you did not enter for.", ScamType.LOTTERY_PRIZE),
            new Rule("JOB_TASK",
                    p("\\b(part[ -]?time (job|work)|work from home|earn (rs\\.?|₹|inr)? ?\\d[\\d,]* ?(per|/|a) ?(day|daily|hour)|like (youtube )?videos|youtube likes|rate (hotels|products)|daily tasks?|task[- ]based|prepaid task)\\b"),
                    30, "Offers easy money for simple online tasks or part-time work. A common task-scam pattern.",
                    ScamType.FAKE_JOB_TASK),
            new Rule("INVESTMENT",
                    p("\\b(guaranteed (returns?|profit)|double your money|\\d+ ?% (daily|weekly|per day|per week|monthly) (returns?|profit)|risk[- ]free (returns?|profit|trading)|vip (trading|stock|investment) group|stock tips group|ipo allotment|crypto (profit|investment))\\b"),
                    30, "Promises guaranteed or unusually high returns. Real investments carry risk.",
                    ScamType.INVESTMENT_TRADING),
            new Rule("LOAN",
                    p("\\b(instant loan|pre[- ]?approved loan|loan (approved|sanctioned)|without (any )?(documents|cibil|credit check)|processing fee)\\b"),
                    20, "Offers an instant or pre-approved loan, often with an upfront fee.", ScamType.LOAN_APP),
            new Rule("ELECTRICITY",
                    p("\\b(electricity|power|bijli)\\b[^.\\n]{0,60}\\b(disconnect(ed|ion)?|cut|discontinu(ed|e))\\b"
                            + "|\\b(disconnect(ed|ion)?)\\b[^.\\n]{0,60}\\b(electricity|power)\\b"),
                    35, "Threatens electricity disconnection and asks you to contact an unofficial number. A common bill scam.",
                    ScamType.ELECTRICITY_BILL),
            new Rule("COURIER",
                    p("\\b(parcel|courier|package|shipment|fedex|dhl|customs)\\b[^.\\n]{0,80}\\b(illegal|drugs|narcotics|seized|held|fake passports?|contraband|customs duty|clearance fee)\\b"),
                    30, "Claims a parcel was seized or needs a fee. Often the start of a fake-police or digital-arrest call.",
                    ScamType.COURIER_CUSTOMS),
            new Rule("AUTHORITY",
                    p("\\b(cbi|enforcement directorate|narcotics|cyber ?cell|police|crime branch|arrest warrant|money laundering|trai|customs officer|rbi officer)\\b"),
                    20, "Invokes police or a government agency to frighten you.", ScamType.IMPERSONATION),
            new Rule("DIGITAL_ARREST",
                    p("\\b(digital(ly)? arrest(ed)?|video call (with|from) (the )?(police|officer|cbi)|stay on (the )?(video )?call)\\b"),
                    45, "Mentions a 'digital arrest'. There is no such thing under Indian law (I4C advisory).",
                    ScamType.IMPERSONATION),
            new Rule("REMOTE_APP",
                    p("\\b(anydesk|teamviewer|quick ?support|rustdesk|screen ?shar(e|ing)|download (this|the) app|install (this|the) app|\\.apk)\\b"),
                    35, "Asks you to install an app or share your screen, which can give control of your phone.",
                    ScamType.OTHER),
            new Rule("UNOFFICIAL_CONTACT",
                    p("\\b(call|whatsapp|contact|sms)\\b[^.\\n]{0,25}(\\+?91[ -]?)?[6-9]\\d{4}[ -]?\\d{5}\\b"),
                    10, "Asks you to call or WhatsApp a personal mobile number instead of the official helpline.", null),
            new Rule("MONEY_DEMAND",
                    p("\\b(pay|transfer|deposit|send)\\b[^.\\n]{0,30}(rs\\.?|₹|inr)\\s?\\d"
                            + "|\\b(registration|security|processing|clearance|verification|refundable) (fee|deposit|charges?)\\b"),
                    15, "Asks you to pay a fee or transfer money.", null),
            new Rule("GENUINE_OTP_NOTICE",
                    p("\\b(do not|don'?t|never) (share|disclose)\\b[^.\\n]{0,30}\\b(otp|pin|password|code)\\b"),
                    -20, "Contains the standard 'do not share your OTP' warning that genuine bank messages carry.",
                    ScamType.NONE)
    );

    private static final Pattern URL = p("\\b((?:https?://|www\\.)[^\\s<>\"']+|[a-z0-9][a-z0-9-]{1,62}(?:\\.[a-z0-9-]{1,62})*\\.(?:com|in|net|org|co|xyz|top|click|live|info|icu|shop|online|site|link|ly|me|cc|tk|ml|ga|cf|gq|buzz|app|vip|club)(?:/[^\\s<>\"']*)?)");
    private static final Set<String> SHORTENERS = Set.of("bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "t.ly", "is.gd",
            "goo.gl", "shorturl.at", "tiny.cc", "ow.ly", "rebrand.ly", "t.co", "s.id", "v.gd", "shorturl.gg", "bitly.ws");
    private static final Set<String> RISKY_TLDS = Set.of("xyz", "top", "click", "live", "info", "icu", "shop", "online",
            "site", "link", "cc", "tk", "ml", "ga", "cf", "gq", "buzz", "vip", "club");
    private static final List<String> BRANDS = List.of("sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe",
            "gpay", "npci", "rbi", "incometax", "indiapost", "aadhaar", "uidai", "kyc", "bob", "pnb", "canara", "bescom",
            "tneb", "mseb", "bsnl", "jio", "airtel");
    private static final List<String> OFFICIAL = List.of("sbi.co.in", "onlinesbi.sbi", "sbi", "hdfcbank.com",
            "icicibank.com", "axisbank.com", "kotak.com", "paytm.com", "phonepe.com", "npci.org.in", "rbi.org.in",
            "gov.in", "nic.in", "uidai.gov.in", "bankofbaroda.in", "pnbindia.in", "canarabank.com", "bescom.co.in",
            "bsnl.co.in", "jio.com", "airtel.in", "amazon.in", "flipkart.com", "google.com");

    public RuleResult analyze(String text) {
        List<Signal> signals = new ArrayList<>();
        int score = 0;
        for (Rule rule : RULES) {
            Matcher m = rule.pattern().matcher(text);
            boolean first = true;
            while (m.find()) {
                signals.add(new Signal(rule.id(), rule.reason(), first ? rule.weight() : 0, m.start(), m.end(), rule.type()));
                if (first) {
                    score += rule.weight();
                    first = false;
                }
            }
        }
        score += analyzeUrls(text, signals);
        // a "do not share OTP" notice only reassures if nothing asks for the OTP/PIN
        boolean asksSecret = signals.stream().anyMatch(s -> s.weight() > 0
                && Set.of("OTP_REQUEST", "PIN_REQUEST", "PIN_TO_RECEIVE").contains(s.id()));
        if (asksSecret) {
            for (int i = 0; i < signals.size(); i++) {
                Signal s = signals.get(i);
                if (s.id().equals("GENUINE_OTP_NOTICE") && s.weight() != 0) {
                    score -= s.weight();
                    signals.set(i, new Signal(s.id(), s.reason(), 0, s.start(), s.end(), ScamType.NONE));
                }
            }
        }
        score = Math.max(0, Math.min(100, score));
        signals.sort(Comparator.comparingInt(Signal::start));
        return new RuleResult(score, dominantType(signals, score), List.copyOf(signals));
    }

    private int analyzeUrls(String text, List<Signal> signals) {
        Matcher m = URL.matcher(text);
        int total = 0;
        boolean anyUrl = false;
        while (m.find()) {
            String raw = m.group(1).replaceAll("[).,;:!?]+$", "");
            int start = m.start(1);
            int end = start + raw.length();
            String host = hostOf(raw);
            if (host.isEmpty() || isOfficial(host) && !host.startsWith("xn--")) {
                if (!host.isEmpty()) {
                    signals.add(new Signal("OFFICIAL_DOMAIN", "Link points to an official domain (" + host + ").", 0, start, end, ScamType.NONE));
                }
                continue;
            }
            anyUrl = true;
            int w = 5;
            List<String> why = new ArrayList<>();
            if (SHORTENERS.contains(host)) {
                w += 20;
                why.add("a URL shortener hides the real destination");
            }
            if (host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                w += 25;
                why.add("the link uses a raw IP address instead of a domain");
            }
            if (host.contains("xn--")) {
                w += 25;
                why.add("the domain uses punycode, which can imitate real letters");
            }
            String tld = host.substring(host.lastIndexOf('.') + 1);
            if (RISKY_TLDS.contains(tld)) {
                w += 15;
                why.add("the ." + tld + " ending is cheap and common in scams");
            }
            String brand = BRANDS.stream().filter(b -> host.replace("-", "").contains(b)).findFirst().orElse(null);
            if (brand != null) {
                w += 35;
                why.add("it looks like '" + brand.toUpperCase(Locale.ROOT) + "' but is not the official domain");
            }
            if (raw.toLowerCase(Locale.ROOT).startsWith("http://")) {
                w += 5;
                why.add("it is not HTTPS");
            }
            String reason = why.isEmpty() ? "Contains a link (" + host + "). Open links only if you trust the sender."
                    : "Suspicious link (" + host + "): " + String.join("; ", why) + ".";
            signals.add(new Signal("SUSPICIOUS_LINK", reason, w, start, end,
                    w >= 20 ? ScamType.PHISHING_LINK : null));
            total = Math.max(total, w);  // the worst link counts
        }
        return anyUrl ? total : 0;
    }

    static String hostOf(String url) {
        String u = url.toLowerCase(Locale.ROOT).replaceFirst("^https?://", "");
        int cut = u.length();
        for (char c : new char[]{'/', '?', '#', ':'}) {
            int i = u.indexOf(c);
            if (i >= 0) {
                cut = Math.min(cut, i);
            }
        }
        String host = u.substring(0, cut).replaceFirst("^www\\.", "");
        try {
            String ascii = IDN.toASCII(host);
            return ascii.isEmpty() ? host : ascii.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return host;
        }
    }

    private static boolean isOfficial(String host) {
        return OFFICIAL.stream().anyMatch(d -> host.equals(d) || host.endsWith("." + d));
    }

    private static ScamType dominantType(List<Signal> signals, int score) {
        if (score < 20) {
            return ScamType.NONE;
        }
        Map<ScamType, Integer> byType = new EnumMap<>(ScamType.class);
        for (Signal s : signals) {
            if (s.scamType() != null && s.scamType() != ScamType.NONE && s.weight() > 0) {
                byType.merge(s.scamType(), s.weight(), Integer::sum);
            }
        }
        return byType.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey)
                .orElse(ScamType.OTHER);
    }
}
