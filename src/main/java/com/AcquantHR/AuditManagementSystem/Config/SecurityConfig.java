package com.AcquantHR.AuditManagementSystem.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.AcquantHR.AuditManagementSystem.Security.CustomUserDetailsService;
import com.AcquantHR.AuditManagementSystem.Security.JwtAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomUserDetailsService userDetailsService;

    // =========================================================
    // CONSTRUCTOR
    // =========================================================

    public SecurityConfig(
            JwtAuthenticationFilter jwtAuthenticationFilter,
            CustomUserDetailsService userDetailsService) {

        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userDetailsService = userDetailsService;
    }

    // =========================================================
    // PASSWORD ENCODER
    // =========================================================

    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }

    // =========================================================
    // AUTHENTICATION PROVIDER
    // =========================================================

    @Bean
    public AuthenticationProvider authenticationProvider() {

        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(userDetailsService);

        provider.setPasswordEncoder(
                passwordEncoder()
        );

        return provider;
    }

    // =========================================================
    // AUTHENTICATION MANAGER
    // =========================================================

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration)
            throws Exception {

        return configuration.getAuthenticationManager();
    }

    // =========================================================
    // SECURITY FILTER CHAIN
    // =========================================================

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http)
            throws Exception {

        http

                // -------------------------------------------------
                // CORS
                // -------------------------------------------------

                .cors(cors -> {})

                // -------------------------------------------------
                // CSRF
                // JWT based API ke liye disable
                // -------------------------------------------------

                .csrf(csrf -> csrf.disable())

                // -------------------------------------------------
                // AUTHORIZATION RULES
                // -------------------------------------------------

                .authorizeHttpRequests(auth -> auth

                        // =================================================
                        // AUTHENTICATION
                        // Login & Register public hain
                        // =================================================

                        .requestMatchers("/api/auth/**")
                        .permitAll()


                        // =================================================
                        // USERS
                        // Sirf ADMIN
                        // =================================================

                        .requestMatchers("/api/users/**")
                        .hasRole("ADMIN")


                        // =================================================
                        // ROLES
                        // Sirf ADMIN
                        // =================================================

                        .requestMatchers("/api/roles/**")
                        .hasRole("ADMIN")


                        // =================================================
                        // AUDITS - GET
                        //
                        // ADMIN:
                        // Full access
                        //
                        // AUDITOR:
                        // View
                        //
                        // COMPLIANCE_OFFICER:
                        // View
                        // =================================================

                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/audits/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "AUDITOR",
                                "COMPLIANCE_OFFICER"
                        )


                        // =================================================
                        // AUDITS - CREATE
                        //
                        // ADMIN + AUDITOR
                        // =================================================

                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/audits/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "AUDITOR"
                        )


                        // =================================================
                        // AUDITS - UPDATE
                        //
                        // ADMIN + AUDITOR
                        // =================================================

                        .requestMatchers(
                                HttpMethod.PUT,
                                "/api/audits/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "AUDITOR"
                        )


                        // =================================================
                        // AUDITS - DELETE
                        //
                        // ADMIN + AUDITOR
                        // =================================================

                        .requestMatchers(
                                HttpMethod.DELETE,
                                "/api/audits/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "AUDITOR"
                        )


                        // =================================================
                        // FINDINGS
                        //
                        // ADMIN + AUDITOR
                        // =================================================

                        .requestMatchers("/api/findings/**")
                        .hasAnyRole(
                                "ADMIN",
                                "AUDITOR"
                        )


                        // =================================================
                        // COMPLIANCE
                        //
                        // ADMIN + COMPLIANCE_OFFICER
                        // =================================================

                        .requestMatchers("/api/compliance/**")
                        .hasAnyRole(
                                "ADMIN",
                                "COMPLIANCE_OFFICER"
                        )


                        // =================================================
                        // ANY OTHER API
                        //
                        // Authentication required
                        // =================================================

                        .anyRequest()
                        .authenticated()
                )

                // -------------------------------------------------
                // SESSION MANAGEMENT
                // JWT = STATELESS
                // -------------------------------------------------

                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )

                // -------------------------------------------------
                // AUTHENTICATION PROVIDER
                // -------------------------------------------------

                .authenticationProvider(
                        authenticationProvider()
                )

                // -------------------------------------------------
                // JWT FILTER
                // UsernamePasswordAuthenticationFilter
                // se pehle JWT filter chalega
                // -------------------------------------------------

                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }
}