/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package uk.ac.ox.ctl.lti13.security.oauth2.client.lti.web;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;

/**
 * This {@code Filter} initiates the authorization code grant or implicit grant flow
 * by redirecting the End-User's user-agent to the Authorization Server's Authorization Endpoint.
 *
 * <p>
 * It builds the OAuth 2.0 Authorization Request,
 * which is used as the redirect {@code URI} to the Authorization Endpoint.
 * The redirect {@code URI} will include the client identifier, requested scope(s), state,
 * response type, and a redirection URI which the authorization server will send the user-agent back to
 * once access is granted (or denied) by the End-User (Resource Owner).
 *
 * <p>
 * By default, this {@code Filter} responds to authorization requests
 * at the {@code URI} {@code /oauth2/authorization/{registrationId}}
 * using the default {@link OAuth2AuthorizationRequestResolver}.
 * The {@code URI} template variable {@code {registrationId}} represents the
 * {@link ClientRegistration#getRegistrationId() registration identifier} of the client
 * that is used for initiating the OAuth 2.0 Authorization Request.
 *
 * <p>
 * The default base {@code URI} {@code /oauth2/authorization} may be overridden
 * via the constructor {@link #OAuth2AuthorizationRequestRedirectFilter(ClientRegistrationRepository, String)},
 * or alternatively, an {@code OAuth2AuthorizationRequestResolver} may be provided to the constructor
 * {@link #OAuth2AuthorizationRequestRedirectFilter(OAuth2AuthorizationRequestResolver)}
 * to override the resolving of authorization requests.

 * @author Joe Grandja
 * @author Rob Winch
 * @since 5.0
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationRequestResolver
 * @see AuthorizationRequestRepository
 * @see ClientRegistration
 * @see ClientRegistrationRepository
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request (Authorization Code)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2">Section 4.2 Implicit Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2.1">Section 4.2.1 Authorization Request (Implicit)</a>
 */
public class OAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {

	private final ThrowableAnalyzer throwableAnalyzer = new DefaultThrowableAnalyzer();
	private final RedirectStrategy authorizationRedirectStrategy = new DefaultRedirectStrategy();
	private OAuth2AuthorizationRequestResolver authorizationRequestResolver;
	private OptimisticAuthorizationRequestRepository authorizationRequestRepository =
		new OptimisticAuthorizationRequestRepository(
				new HttpSessionOAuth2AuthorizationRequestRepository(),
				new StateAuthorizationRequestRepository(Duration.ofMinutes(1))
		);
	private AuthorizationRedirectHandler stateAuthorizationRedirectHandler = new StateAuthorizationRedirectHandler();

	/**
	 * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizationRequestBaseUri the base {@code URI} used for authorization requests
	 */
	public OAuth2AuthorizationRequestRedirectFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                    String authorizationRequestBaseUri) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
		this.authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
				clientRegistrationRepository, authorizationRequestBaseUri);
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
	 *
	 * @since 5.1
	 * @param authorizationRequestResolver the resolver used for resolving authorization requests
	 */
	public OAuth2AuthorizationRequestRedirectFilter(OAuth2AuthorizationRequestResolver authorizationRequestResolver) {
		Assert.notNull(authorizationRequestResolver, "authorizationRequestResolver cannot be null");
		this.authorizationRequestResolver = authorizationRequestResolver;
	}

	/**
	 * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
	 *
	 * @param authorizationRequestRepository the repository used for storing {@link OAuth2AuthorizationRequest}'s
	 */
	public final void setAuthorizationRequestRepository(OptimisticAuthorizationRequestRepository authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		try {
			OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request);
			if (authorizationRequest != null) {
				this.sendRedirectForAuthorization(request, response, authorizationRequest);
				return;
			}
		} catch (Exception failed) {
			this.unsuccessfulRedirectForAuthorization(request, response, failed);
			return;
		}

		try {
			filterChain.doFilter(request, response);
		} catch (IOException ex) {
			throw ex;
		} catch (Exception ex) {
			// Check to see if we need to handle ClientAuthorizationRequiredException
			Throwable[] causeChain = this.throwableAnalyzer.determineCauseChain(ex);
			ClientAuthorizationRequiredException authzEx = (ClientAuthorizationRequiredException) this.throwableAnalyzer
				.getFirstThrowableOfType(ClientAuthorizationRequiredException.class, causeChain);
			if (authzEx != null) {
				try {
					OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestResolver.resolve(request, authzEx.getClientRegistrationId());
					if (authorizationRequest == null) {
						throw authzEx;
					}
					this.sendRedirectForAuthorization(request, response, authorizationRequest);
				} catch (Exception failed) {
					this.unsuccessfulRedirectForAuthorization(request, response, failed);
				}
				return;
			}

			if (ex instanceof ServletException) {
				throw (ServletException) ex;
			} else if (ex instanceof RuntimeException) {
				throw (RuntimeException) ex;
			} else {
				throw new RuntimeException(ex);
			}
		}
	}

	private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
                                              OAuth2AuthorizationRequest authorizationRequest) throws IOException {

		// LTI 1.3 is an implicit grant, but the Spring Security codebase doesn't support this anymore.
		// So we pretend that we are doing an auth code grant.
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
			this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
		}
		
		// Currently in Canvas it always says we support the storage platform, but the mobile apps 
		// currently don't and so shouldn't send through this parameter.
		if (authorizationRequestRepository.hasWorkingSession(request) || hasNoPlatform(request)) {
			// Standard session based usage so we just do a normal browser redirect.
			this.authorizationRedirectStrategy.sendRedirect(request, response, authorizationRequest.getAuthorizationRequestUri());
		} else {
			// Want to pass in the authorizationRequest so we can pass the state to the browser.
			this.stateAuthorizationRedirectHandler.sendRedirect(request, response, authorizationRequest);
		}
		// We don't need to save the request as the final URL to redirect to is in the claims normally we would save
		// the current request here.
	}

	/**
	 * Check that the LTI Storage Platform is unavailable.
	 * @param request The HttpServletRequet to look into.
	 * @return true if the service launching the LTI tool doesn't support the LTI Storage Platform.
	 */
	private boolean hasNoPlatform(HttpServletRequest request) {
		return request.getParameter("lti_storage_target") == null;
	}

	private void unsuccessfulRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response,
                                                      Exception failed) throws IOException, ServletException {

		if (failed instanceof InvalidInitiationRequestException) {
			logger.info("Invalid initiation request: "+ failed);
			response.sendError(HttpStatus.BAD_REQUEST.value(), failed.getMessage());
		} else if (failed instanceof InvalidClientRegistrationIdException) {
			logger.info("Invalid registration ID: "+ failed);
			response.sendError(HttpStatus.NOT_FOUND.value(), failed.getMessage());
		} else {
			logger.error("Authorization Request failed: " + failed.toString(), failed);
			response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
		}
	}

	private static final class DefaultThrowableAnalyzer extends ThrowableAnalyzer {
		protected void initExtractorMap() {
			super.initExtractorMap();
			registerExtractor(ServletException.class, throwable -> {
				ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
				return ((ServletException) throwable).getRootCause();
			});
		}
	}
}
