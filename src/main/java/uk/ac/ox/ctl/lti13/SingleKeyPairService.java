package uk.ac.ox.ctl.lti13;

import java.security.KeyPair;

/**
 * Just uses the same keypair for all operations.
 */
public class SingleKeyPairService implements KeyPairService {

    private final KeyPair keyPair;
    
    private final String keyId;

    public SingleKeyPairService(KeyPair keyPair, String keyId) {
        this.keyPair = keyPair;
        this.keyId = keyId;
    }

    @Override
    public KeyPair getKeyPair(String clientRegistrationId) {
        return keyPair;
    }

    @Override
    public String getKeyId(String clientRegistration) {
        return keyId;
    }
}
