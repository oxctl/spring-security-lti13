package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

/**
 * This is for use when the client sends a request that's missing required parameters.
 */
public class InvalidInitiationRequestException extends RuntimeException {

    /**
     * @param message the exception message
     */
    InvalidInitiationRequestException(String message) {
        super(message);
    }
}
