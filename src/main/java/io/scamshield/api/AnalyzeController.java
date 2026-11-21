package io.scamshield.api;

import java.util.List;

import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.scamshield.api.Dtos.AnalyzeRequest;
import io.scamshield.api.Dtos.AnalyzeResponse;
import io.scamshield.api.Dtos.Example;
import io.scamshield.service.AnalysisService;
import io.swagger.v3.oas.annotations.Operation;

@RestController
@RequestMapping("/api/v1")
public class AnalyzeController {

    private final AnalysisService service;

    public AnalyzeController(AnalysisService service) {
        this.service = service;
    }

    @Operation(summary = "Check a suspicious message, UPI request or URL")
    @PostMapping("/analyze")
    public AnalyzeResponse analyze(@Valid @RequestBody AnalyzeRequest req) {
        return service.analyze(req.text().strip(), req.channel());
    }

    @Operation(summary = "Synthetic example messages for the demo")
    @GetMapping("/examples")
    public List<Example> examples() {
        return Examples.ALL;
    }
}
