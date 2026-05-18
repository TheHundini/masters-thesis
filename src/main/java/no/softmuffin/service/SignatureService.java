package no.softmuffin.service;

import jakarta.validation.constraints.NotBlank;
import no.softmuffin.crypto.keys.KeyManager;
import no.softmuffin.crypto.sign.JwtSigning;
import no.softmuffin.crypto.sign.SignatureAlgorithmSpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class SignatureService {

    private final Map<String, JwtSigning> jwtSigningStrategiesById;
    private final KeyManager keyManager;

    @Autowired
    public SignatureService(final List<JwtSigning> strategies, final KeyManager keyManager) {
        this.jwtSigningStrategiesById = strategies.stream()
                .collect(Collectors.toMap(
                        strategy -> strategy.algorithmId().toUpperCase(Locale.ROOT),
                        Function.identity()
                ));
        this.keyManager = keyManager;
    }

    public SignatureService(final List<JwtSigning> strategies) {
        this(strategies, null);
    }

    public String generateSignedJwt(@NotBlank final String algorithmLabel, final String payload) {
        final JwtSigning strategy = getStrategy(algorithmLabel);
        if (keyManager != null) {
            final KeyPair keyPair = keyManager.getOrCreateKeyPair(algorithmLabel);
            return strategy.signJwt(payload, keyPair.getPrivate());
        }
        return strategy.signJwt(payload);
    }

    public String generateSignedJwt(
            @NotBlank final String algorithmLabel,
            final String payload,
            final PrivateKey privateKey
    ) {
        final JwtSigning strategy = getStrategy(algorithmLabel);
        return strategy.signJwt(payload, privateKey);
    }

    public boolean verifySignedJwt(@NotBlank final String algorithmLabel, final String jwt) {
        final JwtSigning strategy = getStrategy(algorithmLabel);
        if (keyManager != null) {
            final KeyPair keyPair = keyManager.getOrCreateKeyPair(algorithmLabel);
            return strategy.verifyJwt(jwt, keyPair.getPublic());
        }
        return strategy.verifyJwt(jwt);
    }

    public boolean verifySignedJwt(
            @NotBlank final String algorithmLabel,
            final String jwt,
            final PublicKey publicKey
    ) {
        final JwtSigning strategy = getStrategy(algorithmLabel);
        return strategy.verifyJwt(jwt, publicKey);
    }

    private JwtSigning getStrategy(final String algorithmLabel) {
        final String key = SignatureAlgorithmSpec.familyFor(algorithmLabel).toUpperCase(Locale.ROOT);
        final JwtSigning strategy = jwtSigningStrategiesById.get(key);
        if (strategy == null) {
            throw new IllegalArgumentException("Unsupported algorithm: " + key);
        }
        return strategy;
    }
}
