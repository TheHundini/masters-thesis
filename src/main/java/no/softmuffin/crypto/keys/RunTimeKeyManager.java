package no.softmuffin.crypto.keys;

import no.softmuffin.crypto.sign.SignatureAlgorithmSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RunTimeKeyManager implements KeyManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(RunTimeKeyManager.class);
    private static final String PROVIDER_BOUNCY_CASTLE = "BC";

    private final Map<String, KeyPair> keyPairs = new ConcurrentHashMap<>();

    @Override
    public KeyPair getOrCreateKeyPair(final String algorithmName) {
        return keyPairs.computeIfAbsent(normalize(algorithmName), this::generateKeyPairForAlgorithm);
    }

    @Override
    public KeyPair generateKeyPair(final String algorithmName) {
        return generateKeyPairForAlgorithm(normalize(algorithmName));
    }

    private KeyPair generateKeyPairForAlgorithm(final String algorithmName) {
        try {
            final SignatureAlgorithmSpec spec = SignatureAlgorithmSpec.byLabel(algorithmName);
            return switch (spec.family()) {
                case "RSA" -> generateRsaKeyPair(spec.rsaKeyBits());
                case "EC" -> generateEcKeyPair(spec.ecCurve());
                case "ML-DSA" -> generateMldsaKeyPair(spec);
                case "SLH-DSA" -> generateSlhdsaKeyPair(spec);
                default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithmName);
            };
        } catch (GeneralSecurityException e) {
            LOGGER.error("Failed to generate keypair for algorithm {}", algorithmName, e);
            throw new IllegalStateException("Failed to generate keypair for algorithm " + algorithmName, e);
        }
    }

    private KeyPair generateRsaKeyPair(final int keySize) throws NoSuchAlgorithmException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    private KeyPair generateEcKeyPair(final String curveName) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curveName));
        return generator.generateKeyPair();
    }

    private KeyPair generateMldsaKeyPair(final SignatureAlgorithmSpec spec) throws GeneralSecurityException {
        registerBouncyCastleProvider();
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA", PROVIDER_BOUNCY_CASTLE);
        generator.initialize(spec.pqcParameterSpec(), new SecureRandom());
        return generator.generateKeyPair();
    }

    private KeyPair generateSlhdsaKeyPair(final SignatureAlgorithmSpec spec) throws GeneralSecurityException {
        registerBouncyCastleProvider();
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("SLH-DSA", PROVIDER_BOUNCY_CASTLE);
        generator.initialize(spec.pqcParameterSpec(), new SecureRandom());
        return generator.generateKeyPair();
    }

    private static String normalize(final String algorithmName) {
        return SignatureAlgorithmSpec.normalizeAlias(algorithmName);
    }

    private static void registerBouncyCastleProvider() {
        if (Security.getProvider(PROVIDER_BOUNCY_CASTLE) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
