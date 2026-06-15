package no.softmuffin.crypto.sign.classical;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import no.softmuffin.config.JWTDefault;
import no.softmuffin.crypto.keys.KeyManager;
import no.softmuffin.crypto.sign.JwtSigning;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Map;

@Component
public class RSAJwtSigner implements JwtSigning {

    private final KeyPair keyPair;

    public RSAJwtSigner(KeyManager keyManager) {
        this.keyPair = keyManager.getOrCreateKeyPair("RSA-L1");
    }

    @Override
    public String algorithmId() {
        return "RSA";
    }

    @Override
    public String signJwt(String payload) {
        return signJwt(payload, keyPair.getPrivate());
    }

    @Override
    public String signJwt(final String payload, final PrivateKey privateKey) {
        final Algorithm algorithm = algorithmForPrivateKey((RSAPrivateKey) privateKey);
        return createJwt(payload, algorithm);
    }

    @Override
    public boolean verifyJwt(final String jwt) {
        return verifyJwt(jwt, keyPair.getPublic());
    }

    @Override
    public boolean verifyJwt(final String jwt, final PublicKey publicKey) {
        try {
            final JWTVerifier verifier = JWT.require(algorithmForPublicKey((RSAPublicKey) publicKey)).build();
            verifier.verify(jwt);
            return true;
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    private String createJwt(final String payload, final Algorithm algorithm) {
        final Map<String, Object> claims = JWTDefault.defaultClaims(payload);
        final Instant iat = Instant.ofEpochSecond(((Number) claims.get("iat")).longValue());
        final Instant exp = Instant.ofEpochSecond(((Number) claims.get("exp")).longValue());

        final JWTCreator.Builder builder = JWT.create()
                .withIssuer((String) claims.get("iss"))
                .withSubject((String) claims.get("sub"))
                .withIssuedAt(iat)
                .withExpiresAt(exp);

        if (claims.containsKey("payload")) {
            builder.withClaim("payload", (String) claims.get("payload"));
        }

        return builder.sign(algorithm);
    }

    private Algorithm algorithmForPrivateKey(final RSAPrivateKey privateKey) {
        final int keyBits = privateKey.getModulus().bitLength();
        if (keyBits <= 3072) {
            return Algorithm.RSA256(null, privateKey);
        }
        if (keyBits <= 7680) {
            return Algorithm.RSA384(null, privateKey);
        }
        return Algorithm.RSA512(null, privateKey);
    }

    private Algorithm algorithmForPublicKey(final RSAPublicKey publicKey) {
        final int keyBits = publicKey.getModulus().bitLength();
        if (keyBits <= 3072) {
            return Algorithm.RSA256(publicKey, null);
        }
        if (keyBits <= 7680) {
            return Algorithm.RSA384(publicKey, null);
        }
        return Algorithm.RSA512(publicKey, null);
    }
}
