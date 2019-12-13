package uk.ac.ox.ctl.lti13;

import java.security.KeyPair;

/**
 * This maps a client registration ID to a keypair to be used for signing.
 */
public interface KeyPairService {

    /**
     * Gets the key pair to be used to with a particular client.
     * @param clientRegistrationId The client's registration ID.
     * @return The KeyPair to use.
     */
    KeyPair getKeyPair(String clientRegistrationId);
}
