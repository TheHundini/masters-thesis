package no.softmuffin.crypto.sign.pqc;

import no.softmuffin.crypto.sign.ManualJwtSigning;
import no.softmuffin.crypto.sign.PqcSign;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class MldsaJwtSigner extends ManualJwtSigning {

    public MldsaJwtSigner(@Qualifier("bcMldsaSigner") final PqcSign signatureAlgorithm) {
        super(signatureAlgorithm);
    }
}
