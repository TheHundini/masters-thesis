package no.softmuffin.config;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

// TODO: Dont like this implementation...but it is what it is for now.
@Configuration
public class CryptoConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoConfig.class);

    @PostConstruct
    public void registerBc() {
        Security.addProvider(new BouncyCastleProvider());
        LOGGER.info("BouncyCastle PQC provider registered as 'BC'");
    }
}
