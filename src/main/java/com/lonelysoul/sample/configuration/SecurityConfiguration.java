package com.lonelysoul.sample.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static java.time.Duration.ofMinutes;
import static java.util.UUID.randomUUID;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_POST;
import static org.springframework.security.oauth2.server.authorization.client.RegisteredClient.withId;
import static org.springframework.security.oauth2.server.authorization.settings.ClientSettings.builder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    public static final String SPRING_HASH_ALGORITHM_ID_PREFIX = "{argon2@SpringSecurity_v5_8}";

    @Bean
    public Argon2PasswordEncoder getPasswordEncoderForEncoding (){
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8 ();
    }

    private void disableFormLoginAndSession (HttpSecurity security) throws Exception {

        // Disable form login
        security.formLogin (formLogin -> formLogin.disable ())

                // Do not allow storing security information in session
                .sessionManagement (
                        (configuration) -> configuration.sessionCreationPolicy (STATELESS)
                );
    }

    @Bean
    @Order(1)
    public SecurityFilterChain configureAuthorizationServerSecurity (HttpSecurity security) throws Exception {
        disableFormLoginAndSession (security);
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity (security);

        // Enable OpenID Connect 1.0
        security.getConfigurer (OAuth2AuthorizationServerConfigurer.class)
                .oidc (withDefaults ());

        // Return 401 UNAUTHORIZED when not authenticated from the
        // authorization endpoint
        security.exceptionHandling (
                (exceptions) -> exceptions.defaultAuthenticationEntryPointFor (
                        new HttpStatusEntryPoint (UNAUTHORIZED), new AntPathRequestMatcher ("/**")
                )
        )

        // Accept access tokens for user info and/or client registration
        .oauth2ResourceServer ((oauth2) -> oauth2.jwt (withDefaults ()));

        return security.build ();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain configureApiSecurity (HttpSecurity security) throws Exception {
        disableFormLoginAndSession (security);

        // This security configuration would be invoked only for paths that start with /api/
        security.securityMatcher ("/api/**")
                .authorizeHttpRequests (
                        (request) -> request.anyRequest ().authenticated ()
                )

                // Authenticate API JWT Token
                .oauth2ResourceServer (
                        (resourceServer) -> resourceServer.jwt (withDefaults ())
                );

        return security.build ();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository (){
        String clientSecret = SPRING_HASH_ALGORITHM_ID_PREFIX + getPasswordEncoderForEncoding ().encode ("5");

        RegisteredClient testClient = withId (randomUUID ().toString ())
                .clientId ("test-client")
                .clientSecret (clientSecret)
                .clientAuthenticationMethod (CLIENT_SECRET_POST)
                .authorizationGrantType (CLIENT_CREDENTIALS)
                .scope (OidcScopes.OPENID)
                .scope (OidcScopes.PROFILE)
                .clientSettings (builder ()
                        .requireAuthorizationConsent (false)
                        .requireProofKey (false)
                        .build ()
                )
                .tokenSettings (TokenSettings.builder ()
                        .accessTokenTimeToLive (ofMinutes (60L))
                        .build ()
                )
                .build ();

        return new InMemoryRegisteredClientRepository (testClient);
    }
}
