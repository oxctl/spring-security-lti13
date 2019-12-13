package uk.ac.ox.ctl.lti13.nrps;

import com.nimbusds.jose.JOSEException;
import net.minidev.json.JSONObject;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.client.RestTemplate;
import uk.ac.ox.ctl.lti13.OAuth2Interceptor;
import uk.ac.ox.ctl.lti13.TokenRetriever;
import uk.ac.ox.ctl.lti13.lti.Claims;
import uk.ac.ox.ctl.lti13.security.oauth2.client.lti.authentication.OIDCLaunchFlowToken;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;

public class NamesRoleService {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final TokenRetriever tokenRetriever;

    public NamesRoleService(ClientRegistrationRepository clientRegistrationRepository, TokenRetriever tokenRetriever) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.tokenRetriever = tokenRetriever;
    }

    public NRPSResponse getMembers(OIDCLaunchFlowToken oAuth2AuthenticationToken, boolean includeResourceLink) {
        OidcUser principal = oAuth2AuthenticationToken.getPrincipal();
        if (principal != null) {
            Object o = principal.getClaims().get(LtiScopes.LTI_NRPS_CLAIM);
            if (o instanceof JSONObject) {
                JSONObject json = (JSONObject)o;
                String contextMembershipsUrl = json.getAsString("context_memberships_url");
                if (contextMembershipsUrl != null && !contextMembershipsUrl.isEmpty()) {
                    // Got a URL to go to.
                    Object r = principal.getClaims().get(Claims.RESOURCE_LINK);
                    String resourceLinkId = null;
                    if (includeResourceLink && r instanceof JSONObject) {
                        JSONObject resourceJson = (JSONObject) r;
                        resourceLinkId = resourceJson.getAsString("id");
                    }
                    return loadMembers(contextMembershipsUrl, resourceLinkId, oAuth2AuthenticationToken.getClientRegistration().getRegistrationId());
                }
            }
        }
        return null;
    }

    private NRPSResponse loadMembers(String contextMembershipsUrl, String resourceLinkId, String clientRegistrationId) {

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
        if (clientRegistration == null) {
            throw new IllegalStateException("Failed to find client registration for: "+ clientRegistrationId);
        }
        try {
            OAuth2AccessTokenResponse token = tokenRetriever.getToken(clientRegistration, LtiScopes.LTI_NRPS_SCOPE);

            String url = contextMembershipsUrl;
            if (resourceLinkId != null) {
                url = url + "?rlid="+ URLEncoder.encode(resourceLinkId, "UTF-8");
            }
            RestTemplate client = new RestTemplate();
            client.setInterceptors(Collections.singletonList(new OAuth2Interceptor(token.getAccessToken())));
            NRPSResponse response = client.getForObject(url, NRPSResponse.class);
            return response;
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to sign JWT", e);
        } catch (UnsupportedEncodingException e) {
            // This should never happen
            throw new RuntimeException("Unable to find encoding.", e);
        }
    }
}
