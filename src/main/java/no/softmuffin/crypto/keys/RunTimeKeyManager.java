package no.softmuffin.crypto.keys;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RunTimeKeyManager implements KeyManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(RunTimeKeyManager.class);

    private final Map<String, KeyPair> keyPairs = new ConcurrentHashMap<>();

    @Override
    public KeyPair getOrCreateKeyPair(final String algorithmName) {
        return keyPairs.computeIfAbsent(algorithmName.toUpperCase(), this::generateKeyPairForAlgorithm);
    }

    private KeyPair generateKeyPairForAlgorithm(final String alg) {
        try{
            return switch (alg) {
                case "RSA" -> generateRsaKeyPair(2048);
                case "EC" -> generateEcKeyPair("secp256r1");
                case "ML-DSA" -> generateMldsaKeyPair();
                default -> throw new IllegalArgumentException("Unsupported algorithm: " + alg);
            };
        } catch (GeneralSecurityException e) {
            LOGGER.error("Failed to generate keypair for algorithm {}", alg, e);
            throw new IllegalStateException("Failed to generate keypair for algorithm " + alg, e);
        }
    }

    private KeyPair generateRsaKeyPair(final int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        return kpg.generateKeyPair();
    }

    private KeyPair generateEcKeyPair(final String curveName) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec(curveName));
        return kpg.generateKeyPair();
    }

    private KeyPair generateMldsaKeyPair() throws GeneralSecurityException {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        kpg.initialize(MLDSAParameterSpec.ml_dsa_65, new SecureRandom());
        return kpg.generateKeyPair();
    }
}
