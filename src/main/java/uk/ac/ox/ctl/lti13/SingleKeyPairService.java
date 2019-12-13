package uk.ac.ox.ctl.lti13;

import java.security.KeyPair;

/**
 * Just uses the same keypair for all operations.
 */
public class SingleKeyPairService implements KeyPairService {

    private final KeyPair keyPair;

    public SingleKeyPairService(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    @Override
    public KeyPair getKeyPair(String clientRegistrationId) {
        return keyPair;
    }
}
