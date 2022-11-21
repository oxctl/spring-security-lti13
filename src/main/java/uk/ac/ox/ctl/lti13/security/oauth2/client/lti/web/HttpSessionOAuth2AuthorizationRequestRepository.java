/*
 * Copyright 2002-2021 the original author or authors.
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

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AuthorizationRequestRepository} that stores
 * {@link OAuth2AuthorizationRequest} in the {@code HttpSession}. This was copied from Spring Security, but we added
 * support for limiting the number of concurrent sessions, this is so that when we have multiple LTI launches on the
 * same page they work (as the browser will kick them all off at the same time).
 *
 * @author Joe Grandja
 * @author Rob Winch
 * @author Craig Andrews
 * @author Matthew Buckett
 * @since 5.0
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequest
 */
public final class HttpSessionOAuth2AuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME = HttpSessionOAuth2AuthorizationRequestRepository.class
            .getName() + ".AUTHORIZATION_REQUEST";

    private final String sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;

    private int maxConcurrentLogins = 1;

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        Assert.notNull(request, "request cannot be null");
        String stateParameter = this.getStateParameter(request);
        if (stateParameter == null) {
            return null;
        }
        Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(request);
        return authorizationRequests.get(stateParameter);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
                                         HttpServletResponse response) {
        Assert.notNull(request, "request cannot be null");
        Assert.notNull(response, "response cannot be null");
        if (authorizationRequest == null) {
            this.removeAuthorizationRequest(request, response);
            return;
        }
        String state = authorizationRequest.getState();
        Assert.hasText(state, "authorizationRequest.state cannot be empty");
        if (this.maxConcurrentLogins > 1) {
            Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(request);
            authorizationRequests.put(state, authorizationRequest);
            request.getSession().setAttribute(this.sessionAttributeName, authorizationRequests);
        }
        else {
            request.getSession().setAttribute(this.sessionAttributeName, authorizationRequest);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
        Assert.notNull(request, "request cannot be null");
        String stateParameter = this.getStateParameter(request);
        if (stateParameter == null) {
            return null;
        }
        Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(request);
        OAuth2AuthorizationRequest originalRequest = authorizationRequests.remove(stateParameter);
        if (authorizationRequests.size() == 0) {
            request.getSession().removeAttribute(this.sessionAttributeName);
        }
        else if (authorizationRequests.size() == 1) {
            request.getSession().setAttribute(this.sessionAttributeName,
                    authorizationRequests.values().iterator().next());
        }
        else {
            request.getSession().setAttribute(this.sessionAttributeName, authorizationRequests);
        }
        return originalRequest;
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                 HttpServletResponse response) {
        Assert.notNull(response, "response cannot be null");
        return this.removeAuthorizationRequest(request);
    }

    /**
     * Gets the state parameter from the {@link HttpServletRequest}
     * @param request the request to use
     * @return the state parameter or null if not found
     */
    private String getStateParameter(HttpServletRequest request) {
        return request.getParameter(OAuth2ParameterNames.STATE);
    }

    /**
     * Gets a non-null and mutable map of {@link OAuth2AuthorizationRequest#getState()} to
     * an {@link OAuth2AuthorizationRequest}
     * @param request
     * @return a non-null and mutable map of {@link OAuth2AuthorizationRequest#getState()}
     * to an {@link OAuth2AuthorizationRequest}.
     */
    private Map<String, OAuth2AuthorizationRequest> getAuthorizationRequests(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        Object sessionAttributeValue = (session != null) ? session.getAttribute(this.sessionAttributeName) : null;
        if (sessionAttributeValue == null) {
            return new HashMap<>();
        }
        else if (sessionAttributeValue instanceof OAuth2AuthorizationRequest) {
            OAuth2AuthorizationRequest auth2AuthorizationRequest = (OAuth2AuthorizationRequest) sessionAttributeValue;
            Map<String, OAuth2AuthorizationRequest> authorizationRequests = createLRUMap(maxConcurrentLogins);
            authorizationRequests.put(auth2AuthorizationRequest.getState(), auth2AuthorizationRequest);
            return authorizationRequests;
        }
        else if (sessionAttributeValue instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, OAuth2AuthorizationRequest> authorizationRequests = (Map<String, OAuth2AuthorizationRequest>) sessionAttributeValue;
            return authorizationRequests;
        }
        else {
            throw new IllegalStateException(
                    "authorizationRequests is supposed to be a Map or OAuth2AuthorizationRequest but actually is a "
                            + sessionAttributeValue.getClass());
        }
    }

    /**
     * Configure number of  multiple {@link OAuth2AuthorizationRequest}s should be stored per
     * session. Default is 1 (not allow multiple {@link OAuth2AuthorizationRequest}
     * per session).
     * @param maxConcurrentLogins true allows more than one
     * {@link OAuth2AuthorizationRequest} to be stored per session.
     *
     */
    public void setMaxConcurrentLogins(int maxConcurrentLogins) {
        this.maxConcurrentLogins = maxConcurrentLogins;
    }

    /**
     * Creates a least recently used hashmap.
     * @link <a href="https://stackoverflow.com/questions/11469045/how-to-limit-the-maximum-size-of-a-map-by-removing-oldest-entries-when-limit-rea">Stackoverflow</a>
     * @param maxEntries Maximum number of entries in the map
     * @return a LinkedHashMap that limits its size.
     * @param <K> Key type.
     * @param <V> Value type.
     */
    public static <K, V> Map<K, V> createLRUMap(final int maxEntries) {
        return new LinkedHashMap<K, V>(maxEntries*10/7, 0.7f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > maxEntries;
            }
        };
    }

}
