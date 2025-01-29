package uk.ac.ox.ctl.lti13.security.oauth2.core.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * LTI launches can happen when there isn't a user logged in. In this situation
 * there isn't a subject claim and so we need to support this.
 */
public class LtiOauth2User implements OidcUser, Serializable {
    
    public static final String ANONYMOUS = "anonymous";

    private final OidcIdToken idToken;
    private final Set<GrantedAuthority> authorities;
    private final String nameAttributeKey;

    public LtiOauth2User(Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken) {
        this(authorities, idToken, IdTokenClaimNames.SUB);
    }
    /**
     * Constructs a {@code DefaultOAuth2User} using the provided parameters.
     *
     * @param authorities      the authorities granted to the user
     * @param idToken          the ID Token containing claims about the user
     */
    public LtiOauth2User(Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken, String nameAttributeKey) {
        Assert.notNull(idToken, "idToken cannot be null");
        Assert.hasText(nameAttributeKey, "nameAttributeKey cannot be empty");
        this.authorities = (authorities != null)
                ? Collections.unmodifiableSet(new LinkedHashSet<>(this.sortAuthorities(authorities)))
                : Collections.unmodifiableSet(new LinkedHashSet<>(AuthorityUtils.NO_AUTHORITIES));
        this.idToken = idToken;
        this.nameAttributeKey = nameAttributeKey;
    }

    private Set<GrantedAuthority> sortAuthorities(Collection<? extends GrantedAuthority> authorities) {
        SortedSet<GrantedAuthority> sortedAuthorities = new TreeSet<>(
                Comparator.comparing(GrantedAuthority::getAuthority));
        sortedAuthorities.addAll(authorities);
        return sortedAuthorities;
    }

    @Override
    public String getName() {
        String name = idToken.getClaimAsString(nameAttributeKey);
        return name == null ? ANONYMOUS : name;
    }

    @Override
    public Map<String, Object> getClaims() {
        return idToken.getClaims();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        // In the LTI launches we never do additional user lookups so we just always return null.
        return null;
    }

    @Override
    public OidcIdToken getIdToken() {
        return idToken;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return idToken.getClaims();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
}
