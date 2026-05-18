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

    /**
     * Generate a fresh key pair without reusing any cached benchmark state.
     * This is intended for measuring key generation cost in isolation.
     * @param algorithmCode algorithm identifier such as RSA, EC, ML-DSA, or SLH-DSA
     * @return a newly generated KeyPair
     */
    KeyPair generateKeyPair(String algorithmCode);
}
