//package app.secure.configuration;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.core.env.Environment;
//import org.springframework.http.MediaType;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.core.oidc.OidcScopes;
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
//import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.CorsConfigurationSource;
//import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//
//import java.util.Arrays;
//
//@Configuration
//@EnableWebSecurity
//public class AuthorizationServerConfig {
//
//    private final Environment environment;
//
//    public AuthorizationServerConfig(Environment environment) {
//        this.environment = environment;
//    }
//
//    @Bean
//    @Order(2)
//    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception{
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
//                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
////        http
////                // Redirect to the login page when not authenticated from the
////                // authorization endpoint
////                .exceptionHandling((exceptions) -> exceptions
////                        .defaultAuthenticationEntryPointFor(
////                                new LoginUrlAuthenticationEntryPoint("/login"),
////                                new AntPathRequestMatcher("/oauth2/**")
////                        )
////                )
////                // Accept access tokens for User Info and/or Client Registration
////                //.cors(Customizer.withDefaults())
////                .oauth2ResourceServer((resourceServer) -> resourceServer
////                        .jwt(Customizer.withDefaults()));
//
//            http.formLogin(Customizer.withDefaults());
//
//        return  http.cors(Customizer.withDefaults()).build();
//    }
//
//    @Bean
//    @Order(1)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
//            throws Exception {
//        http
//                .authorizeHttpRequests((authorize) -> {
//                    authorize.requestMatchers("/error").permitAll();
//                    authorize.anyRequest().authenticated();
//                        }
//                )
//                // Form login handles the redirect to the login page from the
//                // authorization server filter chain
////                .cors(Customizer.withDefaults())
//                .formLogin(Customizer.withDefaults());
//
//
//        return http.cors(Customizer.withDefaults()).build();
//    }
//
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }
//
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        String clientId = environment.getProperty("spring.security.oauth2.authorization-server.client.registration.testclient.client-id");
//        String clientSecret = environment.getProperty("spring.security.oauth2.authorization-server.client.registration.testclient.client-secret");
//        String redirectUri = environment.getProperty("spring.security.oauth2.authorization-server.client.registration.testclient.redirect-uri");
//        String scope = environment.getProperty("spring.security.oauth2.authorization-server.client.registration.testclient.scope");
//
//        return new InMemoryRegisteredClientRepository(
//                RegisteredClient.withId(clientId)
//                        .clientId(clientId)
//                        .clientSecret(clientSecret)
//                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                        .redirectUri(redirectUri)
//                        .scope(OidcScopes.OPENID)
//                        .scope(OidcScopes.PROFILE)
//                        .scope(OidcScopes.EMAIL)
//                        .build()
//        );
//    }
//
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        CorsConfiguration config = new CorsConfiguration();
//        config.addAllowedHeader("*");
//        config.addAllowedMethod("*");
////        config.addAllowedOrigin("http://localhost:8080");
//        config.setAllowedOrigins(Arrays.asList("http://localhost:8080","http://localhost:9000"));
//        config.setAllowCredentials(true);
//        source.registerCorsConfiguration("/**", config);
//        return source;
//    }
//
//}
