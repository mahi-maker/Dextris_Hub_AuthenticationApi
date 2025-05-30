package com.example.authapi.security;

import com.example.authapi.dto.*;
import com.example.authapi.entity.User;
import com.example.authapi.security.jwt.AuthEntryPointJwt;
import com.example.authapi.security.jwt.AuthTokenFilter;
import com.example.authapi.security.service.UserDetailsImpl;
import com.example.authapi.security.service.UserDetailsServiceImpl;
import com.example.authapi.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }
    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(new AntPathRequestMatcher("/auth/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/swagger-ui/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/v3/api-docs/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()
                        .anyRequest().authenticated()
                );

        http.headers(headers -> headers.frameOptions(frameOption -> frameOption.sameOrigin()));
        http.authenticationProvider(authenticationProvider());
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
//    @Autowired
//    private AuthService authService;
//
//    @Operation(
//            summary = "Register a new user",
//            description = "Creates a new user account and sends verification email"
//    )
//    @ApiResponses({
//            @ApiResponse(responseCode = "200", description = "User registered successfully"),
//            @ApiResponse(responseCode = "400", description = "Invalid input data"),
//            @ApiResponse(responseCode = "409", description = "Email already exists")
//    })
//    @PostMapping("/register")
//    public ResponseEntity<?> registerUser(
//            @Parameter(description = "Registration details", required = true)
//            @Valid @RequestBody RegisterRequest registerRequest) {
//        User user = authService.registerUser(registerRequest);
//        return ResponseEntity.ok(new MessageResponse("User registered successfully! Please check your email for verification."));
//    }
//
//    @Operation(
//            summary = "Authenticate user",
//            description = "Authenticates user credentials and returns JWT token"
//    )
//    @ApiResponses({
//            @ApiResponse(
//                    responseCode = "200",
//                    description = "Authentication successful",
//                    content = @Content(schema = @Schema(implementation = JwtResponse.class))
//            ),
//            @ApiResponse(responseCode = "401", description = "Invalid credentials")
//    })
//    @PostMapping("/login")
//    public ResponseEntity<?> authenticateUser(
//            @Parameter(description = "Login credentials", required = true)
//            @Valid @RequestBody LoginRequest loginRequest) {
//        String jwt = authService.authenticateUser(loginRequest);
//
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//
//        List<String> roles = userDetails.getAuthorities().stream()
//                .map(item -> item.getAuthority())
//                .collect(Collectors.toList());
//
//        return ResponseEntity.ok(new JwtResponse(
//                jwt,
//                userDetails.getId(),
//                userDetails.getEmail(),
//                userDetails.getName(),
//                roles));
//    }
//
//    @Operation(
//            summary = "Verify email",
//            description = "Verifies user email using verification token"
//    )
//    @ApiResponses({
//            @ApiResponse(responseCode = "200", description = "Email verified successfully"),
//            @ApiResponse(responseCode = "400", description = "Invalid or expired token")
//    })
//    @GetMapping("/verify-email")
//    public ResponseEntity<?> verifyEmail(
//            @Parameter(description = "Verification token", required = true)
//            @RequestParam String token) {
//        authService.verifyEmail(token);
//        return ResponseEntity.ok(new MessageResponse("Email verified successfully!"));
//    }
//
//    @Operation(
//            summary = "Resend verification email",
//            description = "Resends verification email to user"
//    )
//    @ApiResponses({
//            @ApiResponse(responseCode = "200", description = "Verification email sent"),
//            @ApiResponse(responseCode = "404", description = "User not found")
//    })
//    @PostMapping("/resend-verification")
//    public ResponseEntity<?> resendVerification(
//            @Parameter(description = "User email", required = true)
//            @RequestParam String email) {
//        authService.resendVerification(email);
//        return ResponseEntity.ok(new MessageResponse("Verification email sent!"));
//    }
//
//    @Operation(
//            summary = "Request password reset",
//            description = "Initiates password reset process by sending email"
//    )
//    @ApiResponses({
//            @ApiResponse(responseCode = "200", description = "Password reset email sent"),
//            @ApiResponse(responseCode = "404", description = "User not found")
//    })
//    @PostMapping("/forgot-password")
//    public ResponseEntity<?> forgotPassword(
//            @Parameter(description = "User email", required = true)
//            @RequestParam String email) {
//        authService.requestPasswordReset(email);
//        return ResponseEntity.ok(new MessageResponse("Password reset email sent!"));
//    }
//
//    @Operation(
//            summary = "Reset password",
//            description = "Resets user password using reset token"
//    )
//    @ApiResponses({
//            @ApiResponse(responseCode = "200", description = "Password reset successful"),
//            @ApiResponse(responseCode = "400", description = "Invalid or expired token")
//    })
//    @PostMapping("/reset-password")
//    public ResponseEntity<?> resetPassword(
//            @Parameter(description = "Password reset details", required = true)
//            @Valid @RequestBody ResetPasswordRequest request) {
//        authService.resetPassword(request);
//        return ResponseEntity.ok(new MessageResponse("Password reset successfully!"));
//    }


}