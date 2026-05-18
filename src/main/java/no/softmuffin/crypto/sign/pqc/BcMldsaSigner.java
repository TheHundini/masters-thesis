package no.softmuffin.crypto.sign.pqc;

import no.softmuffin.crypto.keys.KeyManager;
import no.softmuffin.crypto.sign.PqcSign;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

@Component
public class BcMldsaSigner implements PqcSign {

    private static final Logger LOGGER = LoggerFactory.getLogger(BcMldsaSigner.class);
    private static final String EXTERNAL_NAME = "ML-DSA";

    private final KeyPair keyPair;

    public BcMldsaSigner(KeyManager keyManager) {
        this.keyPair = keyManager.getOrCreateKeyPair("ML-DSA-L3");
        LOGGER.debug("Using key pair for {}", EXTERNAL_NAME);
    }

    @Override
    public String algorithmName() {
        return EXTERNAL_NAME;
    }

    @Override
    public byte[] sign(byte[] message) {
        return sign(message, keyPair.getPrivate());
    }

    @Override
    public byte[] sign(final byte[] message, final PrivateKey privateKey) {
        try {
            final Signature sig = Signature.getInstance("ML-DSA", "BC");
            sig.initSign(privateKey, new SecureRandom());
            sig.update(message);
            byte[] signature = sig.sign();
            LOGGER.debug("Generated {} signature, size={} bytes", EXTERNAL_NAME, signature.length);
            return signature;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign with %s".formatted(EXTERNAL_NAME), e);
        }
    }

    @Override
    public boolean verify(byte[] message, byte[] signature) {
        return verify(message, signature, keyPair.getPublic());
    }

    @Override
    public boolean verify(final byte[] message, final byte[] signature, final PublicKey publicKey) {
        try {
            final Signature sig = Signature.getInstance("ML-DSA", "BC");
            sig.initVerify(publicKey);
            sig.update(message);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to verify %s signature".formatted(EXTERNAL_NAME), e);
        }
    }
}
