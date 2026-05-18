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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Map;

@Component
public class ECJwtSigner implements JwtSigning {

    private final KeyPair keyPair;

    public ECJwtSigner(final KeyManager keyManager) {
        this.keyPair = keyManager.getOrCreateKeyPair("EC-L3");
    }

    @Override
    public String algorithmId() {
        return "EC";
    }

    @Override
    public String signJwt(final String payload) {
        return signJwt(payload, keyPair.getPrivate());
    }

    @Override
    public String signJwt(final String payload, final PrivateKey privateKey) {
        final Algorithm algorithm = algorithmForPrivateKey((ECPrivateKey) privateKey);
        return createJwt(payload, algorithm);
    }

    @Override
    public boolean verifyJwt(final String jwt) {
        return verifyJwt(jwt, keyPair.getPublic());
    }

    @Override
    public boolean verifyJwt(final String jwt, final PublicKey publicKey) {
        try {
            final JWTVerifier verifier = JWT.require(algorithmForPublicKey((ECPublicKey) publicKey)).build();
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

    private Algorithm algorithmForPrivateKey(final ECPrivateKey privateKey) {
        final int fieldSize = privateKey.getParams().getCurve().getField().getFieldSize();
        if (fieldSize <= 256) {
            return Algorithm.ECDSA256(null, privateKey);
        }
        if (fieldSize <= 384) {
            return Algorithm.ECDSA384(null, privateKey);
        }
        return Algorithm.ECDSA512(null, privateKey);
    }

    private Algorithm algorithmForPublicKey(final ECPublicKey publicKey) {
        final int fieldSize = publicKey.getParams().getCurve().getField().getFieldSize();
        if (fieldSize <= 256) {
            return Algorithm.ECDSA256(publicKey, null);
        }
        if (fieldSize <= 384) {
            return Algorithm.ECDSA384(publicKey, null);
        }
        return Algorithm.ECDSA512(publicKey, null);
    }
}
