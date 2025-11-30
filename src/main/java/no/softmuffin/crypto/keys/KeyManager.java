package no.softmuffin.crypto.keys;

import java.security.KeyPair;

public interface KeyManager {

    /**
     * Get or create a keypair for a given algorithm code.
     * Should ensure testability for each iteration.
     * Through interface ensures possiblity for fast switching of specifics
     * @param algorithmCode RS256 or similar, just to specify what key to fetch from map or create.
     * @return KeyPair for the given algorithm
     */
    KeyPair getOrCreateKeyPair(String algorithmCode);
}
