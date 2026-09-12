package com.AcquantHR.AuditManagementSystem.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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

    public SecurityConfig(
            JwtAuthenticationFilter jwtAuthenticationFilter,
            CustomUserDetailsService userDetailsService) {

        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userDetailsService = userDetailsService;
    }


    // =========================================================
    // 1. PASSWORD ENCODER
    // =========================================================

    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }


    // =========================================================
    // 2. AUTHENTICATION PROVIDER
    // =========================================================

    @Bean
    public AuthenticationProvider authenticationProvider() {

        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(userDetailsService);

        provider.setPasswordEncoder(passwordEncoder());

        return provider;
    }


    // =========================================================
    // 3. AUTHENTICATION MANAGER
    // =========================================================

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration)
            throws Exception {

        return configuration.getAuthenticationManager();
    }


    // =========================================================
    // 4. SECURITY FILTER CHAIN
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
                // -------------------------------------------------

                .csrf(csrf -> csrf.disable())


                // -------------------------------------------------
                // AUTHORIZATION
                // -------------------------------------------------

                .authorizeHttpRequests(auth -> auth

                        // =========================================
                        // PUBLIC APIs
                        // =========================================

                        // Login / Register
                        .requestMatchers("/api/auth/**")
                        .permitAll()


                        // =========================================
                        // ADMIN ONLY
                        // =========================================

                        .requestMatchers("/api/users/**")
                        .hasRole("ADMIN")

                        .requestMatchers("/api/roles/**")
                        .hasRole("ADMIN")


                        // =========================================
                        // ADMIN + AUDITOR
                        // =========================================

                        .requestMatchers("/api/audits/**")
                        .hasAnyRole(
                                "ADMIN",
                                "AUDITOR"
                        )

                        .requestMatchers("/api/findings/**")
                        .hasAnyRole(
                                "ADMIN",
                                "AUDITOR"
                        )


                        // =========================================
                        // ADMIN + COMPLIANCE OFFICER
                        // =========================================

                        .requestMatchers("/api/compliance/**")
                        .hasAnyRole(
                                "ADMIN",
                                "COMPLIANCE_OFFICER"
                        )


                        // =========================================
                        // ALL OTHER APIs
                        // =========================================

                        .anyRequest()
                        .authenticated()
                )


                // -------------------------------------------------
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
                // -------------------------------------------------

                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );


        return http.build();
    }
}