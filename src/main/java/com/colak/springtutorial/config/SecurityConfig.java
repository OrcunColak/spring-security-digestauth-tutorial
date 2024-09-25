package com.colak.springtutorial.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // DigestAuthenticationEntryPoint is to send the valid nonce back to the user if authentication fails or to enforce the authentication.
    // It needs a key and a realm name.
    @Bean
    public DigestAuthenticationEntryPoint digestEntryPoint() {
        DigestAuthenticationEntryPoint entryPoint = new DigestAuthenticationEntryPoint();
        entryPoint.setRealmName("demoDigestAuth");
        entryPoint.setKey("571b264a-6868-49e6-9e43-ce80a5749b8f");
        return entryPoint;
    }

    // DigestAuthenticationFilter processes an HTTP request’s Digest authorization headers, putting the result into the SecurityContextHolder.
    // It requires DigestAuthenticationEntryPoint and UserDetailsService to authenticate the user.
    // If authentication is successful, the resulting Authentication object will be placed into the SecurityContextHolder.
    // If authentication fails, an AuthenticationEntryPoint implementation is called.
    // This must always be DigestAuthenticationEntryPoint, which will prompt the user to authenticate again via Digest authentication.
    public DigestAuthenticationFilter digestAuthenticationFilter() {
        DigestAuthenticationFilter authenticationFilter = new DigestAuthenticationFilter();
        authenticationFilter.setUserDetailsService(inMemoryUserDetailsManager());
        authenticationFilter.setCreateAuthenticatedToken(true);
        authenticationFilter.setAuthenticationEntryPoint(digestEntryPoint());
        return authenticationFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)

                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e.authenticationEntryPoint(digestEntryPoint()))
                .addFilterBefore(digestAuthenticationFilter(), DigestAuthenticationFilter.class)

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated()
                );
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    // This is not a bean. I am keeping it as reference only
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        String password = passwordEncoder().encode("password");

        UserDetails user = User.builder()
                .username("user")
                .password(password)
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
