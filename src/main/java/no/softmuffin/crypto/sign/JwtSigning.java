package no.softmuffin.crypto.sign;

public interface JwtSigning {
    String algorithmId();

    /**
     * Generate a signed JWT for given payload (Basicly claims)
     * @param payload claims or random stuff, might not be needed.
     * @return Signed JWT in string value atm...could be converted to Jwt token
     */
    String signJwt(String payload);
}
