package no.softmuffin.api;

import jakarta.validation.Valid;
import no.softmuffin.api.dto.BenchmarkResultDto;
import no.softmuffin.api.dto.SignRequestDto;
import no.softmuffin.api.dto.SignResponseDto;
import no.softmuffin.service.SignatureBenchmarkService;
import no.softmuffin.service.SignatureService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/signature")
public class JwtServerController {

    private final SignatureService signatureService;
    private final SignatureBenchmarkService benchmarkService;
    @Value("${crypto.default-algorithm}")
    private String defaultAlgorithm;

    public JwtServerController(SignatureService signatureService, SignatureBenchmarkService benchmarkService) {
        this.signatureService = signatureService;
        this.benchmarkService = benchmarkService;
    }

    @PostMapping("/token")
    public ResponseEntity<SignResponseDto> sign(@Valid @RequestBody SignRequestDto request) {
        String token = signatureService.generateSignedJwt(request.algorithm(), request.payload());

        return ResponseEntity.ok(new SignResponseDto(request.algorithm(), token));
    }

    @PostMapping("/token/default")
    public ResponseEntity<SignResponseDto> signWithDefault(@Valid @RequestBody String payload) {
        String token = signatureService.generateSignedJwt(defaultAlgorithm, payload);
        return ResponseEntity.ok(new SignResponseDto(defaultAlgorithm, token));
    }

    @PostMapping("/bench")
    public ResponseEntity<BenchmarkResultDto> benchmark(
            @RequestParam String algorithm,
            @RequestParam(defaultValue = "1000") int iterations,
            @RequestParam(defaultValue = "benchmark-payload") String payload) {
        BenchmarkResultDto resultDto =
                benchmarkService.runSignatureBenchmark(algorithm, iterations, payload);

        return ResponseEntity.ok(resultDto);
    }
}
