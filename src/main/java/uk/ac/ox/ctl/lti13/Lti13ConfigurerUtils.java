package uk.ac.ox.ctl.lti13;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

class Lti13ConfigurerUtils {

    static <B extends HttpSecurityBuilder<B>> ClientRegistrationRepository getClientRegistrationRepository(B builder) {
        ClientRegistrationRepository clientRegistrationRepository = builder.getSharedObject(ClientRegistrationRepository.class);
        if (clientRegistrationRepository == null) {
            clientRegistrationRepository = getClientRegistrationRepositoryBean(builder);
            builder.setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
        }
        return clientRegistrationRepository;
    }

    private static <B extends HttpSecurityBuilder<B>> ClientRegistrationRepository getClientRegistrationRepositoryBean(B builder) {
        return builder.getSharedObject(ApplicationContext.class).getBean(ClientRegistrationRepository.class);
    }

}
