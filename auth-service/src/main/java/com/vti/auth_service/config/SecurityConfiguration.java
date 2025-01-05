package com.vti.auth_service.config;
import com.vti.auth_service.handler.OAuth2AuthenticationFailureHandler;
import com.vti.auth_service.model.Role;
import com.vti.auth_service.handler.OAuth2AuthenticationSuccessHandler;
import com.vti.auth_service.oauth2.repository.HttpCookieOAuthorizationRequestRepository;
import com.vti.auth_service.oauth2.service.CustomOAuth2UserService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfiguration {
    private static final String[] WHITE_LIST_URL = {
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh-token"
    };


    private CustomOAuth2UserService customOAuth2UserService;


    private HttpCookieOAuthorizationRequestRepository httpCookieOAuthorizationRequestRepository;


    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;


    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @SuppressWarnings("removal")
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .csrf().disable()
                .authorizeRequests(req -> req
                        .requestMatchers(WHITE_LIST_URL).permitAll()
                        .requestMatchers("/api/v1/accounts").hasAnyRole(Role.ADMIN.name(), Role.MANAGER.name())
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(oauth2Login -> oauth2Login
                        .authorizationEndpoint(authorization -> authorization
                                .baseUri("/oauth2/authorize")
                                .authorizationRequestRepository(httpCookieOAuthorizationRequestRepository)
                        )
                        .redirectionEndpoint(redirection -> redirection
                                .baseUri("/login/oauth2/code/*") // Update this to match your redirect URI
                        )
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService)
                        )
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler)
                );

        return http.build();
    }


}