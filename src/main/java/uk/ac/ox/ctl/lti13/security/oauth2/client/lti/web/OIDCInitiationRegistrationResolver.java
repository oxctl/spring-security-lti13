package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;


import jakarta.servlet.http.HttpServletRequest;

/**
 * Interface to allow custom ways of resolving the registration ID. Eg by client ID, or deployment ID.
 */
public interface OIDCInitiationRegistrationResolver {

    /*
     ** Finds a registration out of a request during a login initiation.
     */
    String resolve(HttpServletRequest request);
}
