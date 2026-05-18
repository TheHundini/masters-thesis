package no.softmuffin.crypto.sign.pqc;

import no.softmuffin.crypto.keys.RunTimeKeyManager;
import no.softmuffin.crypto.sign.PqcSign;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PqcSignContractTest {

    @Test
    @DisplayName("PQC signers verify their own signatures and reject tampering")
    void pqcSignersFollowSignatureContract() {
        for (PqcSign signer : pqcSigners()) {
            final byte[] message = "important benchmark payload".getBytes(StandardCharsets.UTF_8);
            final byte[] signature = signer.sign(message);

            assertThat(signature)
                    .as("%s signature bytes", signer.algorithmName())
                    .isNotEmpty();
            assertThat(signer.verify(message, signature))
                    .as("%s verifies original message", signer.algorithmName())
                    .isTrue();
            assertThat(signer.verify("changed payload".getBytes(StandardCharsets.UTF_8), signature))
                    .as("%s rejects changed message", signer.algorithmName())
                    .isFalse();

            signature[0] = (byte) (signature[0] ^ 1);
            assertThat(signer.verify(message, signature))
                    .as("%s rejects changed signature", signer.algorithmName())
                    .isFalse();
        }
    }

    private List<PqcSign> pqcSigners() {
        final RunTimeKeyManager keyManager = new RunTimeKeyManager();
        return List.of(
                new BcMldsaSigner(keyManager),
                new BcSlhdsaSigner(keyManager)
        );
    }
}
