package io.scamshield.api;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import io.scamshield.llm.LlmAnalyzer;
import io.scamshield.llm.LlmVerdict;
import io.scamshield.rag.AdvisoryStore;
import io.scamshield.rag.AdvisoryStore.Advisory;
import io.scamshield.rules.RuleEngine;
import io.scamshield.rules.ScamType;
import io.scamshield.service.AnalysisService;

@WebMvcTest(AnalyzeController.class)
@Import({AnalysisService.class, RuleEngine.class})
class AnalyzeControllerTest {

    @Autowired
    MockMvc mvc;

    @MockitoBean
    LlmAnalyzer llm;

    @MockitoBean
    AdvisoryStore advisories;

    private static final String KYC = "{\"text\":\"Your SBI account will be blocked today. Update KYC at http://sbi-kyc.xyz/a\",\"channel\":\"sms\"}";

    @Test
    void hybridVerdictBlendsRuleAndLlmScoresAndMapsCitations() throws Exception {
        when(advisories.search(anyString())).thenReturn(List.of(
                new Advisory("Advisory A", "https://example.gov.in/a", "Publisher A", "2025-01-01", "text", 0.9)));
        when(llm.analyze(anyString(), any(), any(), any())).thenReturn(Optional.of(new LlmVerdict(
                "Likely Scam", 90, ScamType.FAKE_KYC_ACCOUNT_BLOCK, List.of(), "Fake KYC message.", List.of(1, 7),
                List.of("Delete it."))));

        mvc.perform(post("/api/v1/analyze").contentType(MediaType.APPLICATION_JSON).content(KYC))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("hybrid"))
                .andExpect(jsonPath("$.verdict").value("Likely Scam"))
                .andExpect(jsonPath("$.llmScore").value(90))
                .andExpect(jsonPath("$.scamType").value("Fake KYC / account-block"))
                .andExpect(jsonPath("$.citations.length()").value(1))  // index 7 does not exist and is dropped
                .andExpect(jsonPath("$.citations[0].url").value("https://example.gov.in/a"))
                .andExpect(jsonPath("$.redFlags[0].source").value("rule"));
    }

    @Test
    void fallsBackToRulesWhenLlmFails() throws Exception {
        when(advisories.search(anyString())).thenReturn(List.of());
        when(llm.analyze(anyString(), any(), any(), any())).thenReturn(Optional.empty());

        mvc.perform(post("/api/v1/analyze").contentType(MediaType.APPLICATION_JSON).content(KYC))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("rules-only"))
                .andExpect(jsonPath("$.llmScore").doesNotExist())
                .andExpect(jsonPath("$.verdict").value("Likely Scam"));
    }

    @Test
    void rejectsEmptyText() throws Exception {
        mvc.perform(post("/api/v1/analyze").contentType(MediaType.APPLICATION_JSON).content("{\"text\":\"  \"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    void listsExamples() throws Exception {
        mvc.perform(get("/api/v1/examples")).andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(7));
    }
}
