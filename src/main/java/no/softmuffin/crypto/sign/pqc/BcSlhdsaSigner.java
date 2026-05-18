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
public class BcSlhdsaSigner implements PqcSign {

    private static final Logger LOGGER = LoggerFactory.getLogger(BcSlhdsaSigner.class);
    private static final String EXTERNAL_NAME = "SLH-DSA";

    private final KeyPair keyPair;

    public BcSlhdsaSigner(KeyManager keyManager) {
        this.keyPair = keyManager.getOrCreateKeyPair("SLH-DSA-L3");
        LOGGER.debug("Using key pair for {}", EXTERNAL_NAME);
    }

    @Override
    public String algorithmName() {
        return EXTERNAL_NAME;
    }

    @Override
    public byte[] sign(byte[] data) {
        return sign(data, keyPair.getPrivate());
    }

    @Override
    public byte[] sign(final byte[] data, final PrivateKey privateKey) {
        try {
            final Signature signature = Signature.getInstance("SLH-DSA", "BC");
            signature.initSign(privateKey, new SecureRandom());
            signature.update(data);
            byte[] signed = signature.sign();
            LOGGER.debug("Generated {} signature, size={} bytes", EXTERNAL_NAME, signed.length);
            return signed;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign with %s".formatted(EXTERNAL_NAME), e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] signed) {
        return verify(data, signed, keyPair.getPublic());
    }

    @Override
    public boolean verify(final byte[] data, final byte[] signed, final PublicKey publicKey) {
        try {
            final Signature signature = Signature.getInstance("SLH-DSA", "BC");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signed);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to verify %s signature".formatted(EXTERNAL_NAME), e);
        }
    }
}
