package com.ken.app.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class JwtSecurityConfig {

    // JWT Authentication using Spring Boot's OAuth2
    // 1. Create Key Pair
    // 2. Create RSA KEy object using Key Pair
    // 3. Create JWKSource(JSON Web Key source)
    // 4. RSA Public Key for decoding

    // JWT Flow
    // 1. Create a JWT
    // -> Needs Encoding - 1. User Credentials 2. User data (payload) 3. RSA key pair
    // 2. Send JWT as part of request header
    // -> Authorization Header, Bearer Token, Authorization:Bearer ${JWT_TOKEN}
    // 3. JWT is verified
    // -> Needs Decoding, RSA key pair (Public Key)

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                auth -> {
                    auth.anyRequest().authenticated();
                }
        );
        http.sessionManagement(
                session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        http.httpBasic();
        http.csrf().disable();
        http.headers().frameOptions().sameOrigin();
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }

    @Bean
    public DataSource dataSource(){
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    // User Credential in H2 Database depends on roles(admin,user)
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        var user = User.withUsername("ken")
                // .password("{noop}lee")
                .password("lee").passwordEncoder(str -> passwordEncoder().encode(str))
                .roles("USER")
                .build();
        var admin = User.withUsername("katie")
                //.password("{noop}lee")
                .password("lee").passwordEncoder(str -> passwordEncoder().encode(str))
                .roles("ADMIN")
                .build();

        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    // Store bcrypt encoded passwords.
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // JWT Authentication using Spring Boot's OAuth2

    // 1. Create Key Pair
    @Bean
    public KeyPair keyPair()  {
        try{
            var keyPariGenerator =  KeyPairGenerator.getInstance("RSA");
            keyPariGenerator.initialize(2048);
            return keyPariGenerator.generateKeyPair();
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    // 2. Create RSA KEy object using Key Pair
    // com.nimbusds.jose.jwk.RSAKey
    @Bean
    public com.nimbusds.jose.jwk.RSAKey rsaKey(KeyPair keyPair) {
        return new RSAKey
                .Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    // 3. Create JWKSource(JSON Web Key source)
    // com.nimbusds.jose.jwk.source.JWKSource;
    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey){
        var jwkSet = new JWKSet(rsaKey);

        return ((jwkSelector, context) -> jwkSelector.select(jwkSet));
        /*var jwkSource = new JWKSource() {
            @Override
            public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
                return jwkSelector.select(jwkSet);
            }
        };*/
    }

    // 4. RSA Public Key for decoding
    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey())
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
}
