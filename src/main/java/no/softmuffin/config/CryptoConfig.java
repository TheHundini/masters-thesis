package no.softmuffin.config;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

@Configuration
public class CryptoConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoConfig.class);

    @PostConstruct
    public void registerBouncyCastleProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            LOGGER.info("Bouncy Castle provider registered as '{}'", BouncyCastleProvider.PROVIDER_NAME);
        }
    }
}
