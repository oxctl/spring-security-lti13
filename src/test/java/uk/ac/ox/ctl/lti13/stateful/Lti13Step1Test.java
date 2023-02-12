package uk.ac.ox.ctl.lti13.stateful;


import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import uk.ac.ox.ctl.lti13.config.Lti13Configuration;

import jakarta.servlet.http.Cookie;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@SpringJUnitWebConfig(classes = {Lti13Configuration.class})
public class Lti13Step1Test {

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext wac;

    @Before
    public void setup() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(wac)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    public void testSecured() throws Exception {
        this.mockMvc.perform(get("/"))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testStep1Unknown() throws Exception {
        this.mockMvc.perform(post("/lti/login_initiation/unknown"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testStep1Empty() throws Exception {
        this.mockMvc.perform(post("/lti/login_initiation/test"))
                .andExpect(status().is5xxServerError());
    }

    @Test
    public void testStep1Complete() throws Exception {
        this.mockMvc.perform(post("/lti/login_initiation/test")
                    .param("iss", "https://test.com")
                    .param("login_hint", "hint")
                    .param("target_link_uri", "https://localhost/")
                    .cookie(new Cookie("WORKING_COOKIES", "true"))
                )
                .andExpect(status().is3xxRedirection())
                // We can't test the cookie as this is done by Spring Security and not the controller
                .andExpect(redirectedUrlPattern("https://platform.test/auth/**"));
    }


    @Test
    public void testStep1NoStorageTarget() throws Exception {
        // There's no explicit support for the LTI storage platform so we assume that we can't use it and just
        // redirect
        this.mockMvc.perform(post("/lti/login_initiation/test")
                        .param("iss", "https://test.com")
                        .param("login_hint", "hint")
                        .param("target_link_uri", "https://localhost/")
                )
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("https://platform.test/auth/**"));
    }

}
