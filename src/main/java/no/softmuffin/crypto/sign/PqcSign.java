package no.softmuffin.crypto.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface PqcSign {
    String algorithmName();

    byte[] sign(byte[] message);

    boolean verify(byte[] data, byte[] signature);

    byte[] sign(byte[] message, PrivateKey privateKey);

    boolean verify(byte[] message, byte[] signature, PublicKey publicKey);
}
