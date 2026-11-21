package io.scamshield.api;

import java.util.List;

import io.scamshield.api.Dtos.Example;

/** Synthetic examples only: invented names, numbers, domains and amounts. */
final class Examples {

    private Examples() {
    }

    static final List<Example> ALL = List.of(
            new Example("kyc", "Fake KYC SMS", "sms",
                    "Dear Customer, your SBI YONO account will be blocked today due to pending KYC. "
                            + "Update PAN immediately: http://sbi-yono-kyc.xyz/update or call 9876500000."),
            new Example("upi", "UPI collect request", "upi",
                    "Hi, I am buying your sofa from the marketplace. I have sent Rs 12,500 to your UPI. "
                            + "Please approve the payment request and enter your UPI PIN to receive the money."),
            new Example("otp", "Genuine bank OTP", "sms",
                    "482913 is your OTP for a transaction of INR 1,250.00 at an online store on your card ending 0000. "
                            + "Valid for 10 minutes. Do not share this OTP with anyone. - Example Bank"),
            new Example("job", "Part-time job offer", "whatsapp",
                    "Hello! Part time job offer: earn Rs 3000 per day by liking YouTube videos. "
                            + "Pay a refundable registration fee of Rs 500 to start. Join our Telegram group now."),
            new Example("electricity", "Electricity disconnection", "sms",
                    "Dear consumer, your electricity power will be disconnected tonight at 9.30 pm because your "
                            + "previous month bill was not updated. Please contact our officer 8000012345 immediately."),
            new Example("arrest", "Digital arrest call", "whatsapp",
                    "This is Inspector from Mumbai Cyber Crime. A FedEx parcel in your name containing drugs was seized "
                            + "by customs. You are under digital arrest. Stay on this video call and do not tell anyone."),
            new Example("delivery", "Delivery update", "sms",
                    "Your order of 2 items has been shipped and will arrive on Friday. Track it in the shopping app.")
    );
}
