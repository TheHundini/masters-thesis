package no.softmuffin.crypto.sign.pqc;

import no.softmuffin.crypto.keys.KeyManager;
import no.softmuffin.crypto.sign.PqcSign;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;

@Component
public class BcSlhdsaSigner implements PqcSign {

    private static final Logger LOGGER = LoggerFactory.getLogger(BcSlhdsaSigner.class);
    private static final String EXTERNAL_NAME = "SLH-DSA";

    // This is not very statefull atm :)
    private final KeyPair keyPair;

    public BcSlhdsaSigner(KeyManager keyManager) {
        this.keyPair = keyManager.getOrCreateKeyPair(EXTERNAL_NAME);
        LOGGER.info("Using key pair for {}", EXTERNAL_NAME);
    }

    @Override
    public String algorithmName() {
        return EXTERNAL_NAME;
    }

    @Override
    public byte[] sign(byte[] data) {
        try {
            final Signature signature = Signature.getInstance("SLH-DSA", "BC");
            signature.initSign(keyPair.getPrivate(), new SecureRandom());
            signature.update(data);
            byte[] signed = signature.sign();
            LOGGER.debug("Generated {} signature, size={} bytes", EXTERNAL_NAME, signed.length);
            return signed;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign with %s".formatted(EXTERNAL_NAME), e);
        }
    }

    public boolean verify(byte[] data, byte[] signed) {
        try {
            final Signature signature = Signature.getInstance("SLH-DSA", "BC");
            signature.initVerify(keyPair.getPublic());
            signature.update(data);
            return signature.verify(signed);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to verify %s signature".formatted(EXTERNAL_NAME), e);
        }
    }
}
