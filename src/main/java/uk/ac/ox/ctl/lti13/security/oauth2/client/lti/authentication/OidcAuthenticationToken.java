package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;

/**
 * We are validating the state on the client (browser) so we need to be able to return the state/nonce back to the client
 * and so it needs to exist outside of just the authentication method.
 */
public class OidcAuthenticationToken extends OAuth2AuthenticationToken {
	private final String state;

	public OidcAuthenticationToken(OAuth2User principal, Collection<? extends GrantedAuthority> authorities, String authorizedClientRegistrationId, String state) {
		super(principal, authorities, authorizedClientRegistrationId);
		this.state = state;
	}

	/**
	 * @return returns the state that was passed in with the authentication.
	 */
	public String getState() {
		return state;
	}
}
