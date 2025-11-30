package no.softmuffin.crypto.sign.classical;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import no.softmuffin.config.JWTDefault;
import no.softmuffin.crypto.keys.KeyManager;
import no.softmuffin.crypto.sign.JwtSigning;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Map;

@Component
public class RSAJwtSigner implements JwtSigning {

    private final KeyPair keyPair;

    public RSAJwtSigner(KeyManager keyManager) {
        this.keyPair = keyManager.getOrCreateKeyPair("RSA");
    }

    @Override
    public String algorithmId() {
        return "RSA";
    }

    @Override
    public String signJwt(String payload) {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        Algorithm alg = Algorithm.RSA256(publicKey, privateKey);

        Map<String, Object> claims = JWTDefault.defaultClaims(payload);

        Instant iat = Instant.ofEpochSecond(((Number) claims.get("iat")).longValue());
        Instant exp = Instant.ofEpochSecond(((Number) claims.get("exp")).longValue());

        JWTCreator.Builder builder = JWT.create()
                .withIssuer((String) claims.get("iss"))
                .withSubject((String) claims.get("sub"))
                .withIssuedAt(iat)
                .withExpiresAt(exp);

        if (claims.containsKey("payload")) {
            builder.withClaim("payload", (String) claims.get("payload"));
        }

        return builder.sign(alg);
    }
}
