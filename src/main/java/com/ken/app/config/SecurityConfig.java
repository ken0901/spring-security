package com.ken.app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;

import javax.sql.DataSource;

// Spring Security
@Configuration
@EnableMethodSecurity(jsr250Enabled=true, securedEnabled = true)
public class SecurityConfig {

    // Spring Security Authorization
    // 1. Global Security: authorizeHttpRequests
    // 2. Method Security(@EnableMethodSecurity)
    // -> @Pre and @Post annotations - @PreAuthorize, @PostAuthorize
    // -> JSR-250 annotations - @EnableMethodSecurity(jsr250Enabled=true), @RolesAllowed({"ADMIN","USER"})
    // -> @Secured annotation - @EnableMethodSecurity(securedEnabled = true) and @Secured({"ADMIN","USER"})

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                auth -> {
                    auth
                        .requestMatchers("/users").hasRole("USER")
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated();
                }
        );
        http.sessionManagement(
                session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        //http.formLogin();
        http.httpBasic();
        http.csrf().disable();
        http.headers().frameOptions().sameOrigin();
        return http.build();
    }

    // User Credential in memory
    /*
    @Bean
    public UserDetailsService  userDetailsService() {
        var user = User.withUsername("ken")
                .password("{noop}lee")
                .roles("USER")
                .build();
        var admin = User.withUsername("katie")
                .password("{noop}lee")
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user,admin);
    }
    */

    @Bean
    public DataSource dataSource(){
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    // User Credential in H2 Database depends on roles(admin,user)
    @Bean
    public UserDetailsService  userDetailsService(DataSource dataSource) {
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

    // Cross-Origin Resource Sharing (CORS):
    // Specification that allows you to configure which cross-domain requests are allowed
    /*
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedMethods("*")
                        .allowedOrigins("http://localhost:3000");
            }
        };
    }
     */
}
