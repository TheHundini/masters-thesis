package no.softmuffin.service;

import jakarta.validation.constraints.NotBlank;
import no.softmuffin.crypto.sign.JwtSigning;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class SignatureService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignatureService.class);

    private final Map<String, JwtSigning> jwtSigningStrategiesById;

    public SignatureService(final List<JwtSigning> strategies) {
        this.jwtSigningStrategiesById = strategies.stream()
                .collect(Collectors.toMap(
                        s -> s.algorithmId().toUpperCase(),
                        Function.identity()
                ));
        //LOGGER.info("Registered JWT strategies: {}", jwtSigningStrategiesById.keySet());
    }

    public String generateSignedJwt(@NotBlank final String algorithmLabel, final String payload) {
        final JwtSigning strategy = getStrategy(algorithmLabel);

        //LOGGER.debug("Using strategy {} for algorithm {}", strategy.getClass().getSimpleName(), algorithmLabel);
        return strategy.signJwt(payload);
    }

    public boolean verifySignedJwt(@NotBlank final String algorithmLabel, final String jwt) {
        final JwtSigning strategy = getStrategy(algorithmLabel);
        //LOGGER.debug("Using strategy {} for algorithm {}", strategy.getClass().getSimpleName(), algorithmLabel);
        return strategy.verifyJwt(jwt);
    }

    private JwtSigning getStrategy(final String algorithmLabel) {
        final String key = algorithmLabel.trim().toUpperCase();
        final JwtSigning strategy = jwtSigningStrategiesById.get(key);
        if (strategy == null) {
            throw new IllegalArgumentException("Unsupported algorithm: " + key);
        }
        return strategy;
    }
}
