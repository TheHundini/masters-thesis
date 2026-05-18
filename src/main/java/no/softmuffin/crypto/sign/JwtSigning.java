package no.softmuffin.crypto.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface JwtSigning {
    String algorithmId();

    /**
     * Generate a signed JWT for the given payload.
     * @param payload payload value to include in the token claims
     * @return signed JWT string
     */
    String signJwt(String payload);

    boolean verifyJwt(String jwt);

    String signJwt(String payload, PrivateKey privateKey);

    boolean verifyJwt(String jwt, PublicKey publicKey);
}
