package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public interface LTIAuthorizationGrantType {

    /**
     * The LTI grant type when launching a tool.This is needed because Spring Security itself 
     * doesn't support the implicit grant type anymore.
     */
    AuthorizationGrantType IMPLICIT = new AuthorizationGrantType("implicit");
}
