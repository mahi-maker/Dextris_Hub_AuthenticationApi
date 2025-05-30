package com.example.authapi.service;

import com.example.authapi.dto.LoginRequest;
import com.example.authapi.dto.RegisterRequest;
import com.example.authapi.dto.ResetPasswordRequest;
import com.example.authapi.entity.ERole;
import com.example.authapi.entity.Role;
import com.example.authapi.entity.User;
import com.example.authapi.entity.UserType;
import com.example.authapi.repository.RoleRepository;
import com.example.authapi.repository.UserRepository;
import com.example.authapi.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

//

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private EmailService emailService;

    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthService(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Transactional
    public User registerUser(RegisterRequest request) {
        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Error: Email is already in use!");
        }

        // Create new user's account
        User user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .phone(request.getPhone())
                .userType(request.getUserType())
                .enabled(false)
                .accountNonLocked(true)
                .failedAttempt(0)
                .build();

        user.generateVerificationToken();

        Set<Role> roles = new HashSet<>();
        
        // Add default ROLE_USER to all users
        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role USER is not found."));
        roles.add(userRole);
        
        // Add specific role based on user type
        if (request.getUserType() == UserType.JOBSEEKER) {
            Role jobseekerRole = roleRepository.findByName(ERole.ROLE_JOBSEEKER)
                    .orElseThrow(() -> new RuntimeException("Error: Role JOBSEEKER is not found."));
            roles.add(jobseekerRole);
        } else if (request.getUserType() == UserType.EMPLOYER) {
            Role employerRole = roleRepository.findByName(ERole.ROLE_EMPLOYER)
                    .orElseThrow(() -> new RuntimeException("Error: Role EMPLOYER is not found."));
            roles.add(employerRole);
        }
        
        user.setRoles(roles);
        User savedUser = userRepository.save(user);
        
        // Send verification email
        emailService.sendVerificationEmail(user.getEmail(), user.getVerificationToken());
        
        return savedUser;
    }

    public String authenticateUser(LoginRequest loginRequest) {
        try {
            // Attempt authentication
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
            
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            // Reset failed attempts for successful login
            User user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow(
                    () -> new RuntimeException("User not found"));
            
            if (user.getFailedAttempt() > 0) {
                resetFailedAttempts(user.getEmail());
            }
            
            // Generate JWT token
            return jwtUtils.generateJwtToken(authentication);
            
        } catch (AuthenticationException e) {
            // Increment failed attempts on authentication failure
            Optional<User> userOptional = userRepository.findByEmail(loginRequest.getEmail());
            
            if (userOptional.isPresent()) {
                User user = userOptional.get();
                
                // Check if account is already locked
                if (user.isAccountNonLocked()) {
                    if (user.getFailedAttempt() < MAX_FAILED_ATTEMPTS - 1) {
                        increaseFailedAttempts(user);
                    } else {
                        lockUser(user);
                        throw new RuntimeException("Your account has been locked due to 5 failed attempts. It will be unlocked after 24 hours.");
                    }
                } else if (unlockWhenTimeExpired(user)) {
                    throw new RuntimeException("Your account has been unlocked. Please try again.");
                } else {
                    throw new RuntimeException("Your account is locked. Please try again later.");
                }
            }
            
            throw new RuntimeException("Invalid email or password");
        }
    }

    @Transactional
    public void verifyEmail(String token) {
        User user = userRepository.findByVerificationToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));
        
        if (!user.isVerificationTokenValid()) {
            throw new RuntimeException("Verification token has expired");
        }
        
        user.setEnabled(true);
        user.setVerificationToken(null);
        user.setVerificationTokenExpiry(null);
        
        userRepository.save(user);
    }

    @Transactional
    public void resendVerification(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
        
        if (user.isEnabled()) {
            throw new RuntimeException("Email is already verified");
        }
        
        user.generateVerificationToken();
        userRepository.save(user);
        
        emailService.sendVerificationEmail(user.getEmail(), user.getVerificationToken());
    }

    @Transactional
    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with email: " + email));
        
        user.generateResetPasswordToken();
        userRepository.save(user);
        
        emailService.sendPasswordResetEmail(user.getEmail(), user.getResetPasswordToken());
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        User user = userRepository.findByResetPasswordToken(request.getToken())
                .orElseThrow(() -> new RuntimeException("Invalid reset token"));
        
        if (!user.isResetPasswordTokenValid()) {
            throw new RuntimeException("Reset token has expired");
        }
        
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setResetPasswordToken(null);
        user.setResetPasswordTokenExpiry(null);
        
        userRepository.save(user);
    }

    @Transactional
    public void increaseFailedAttempts(User user) {
        int newFailedAttempts = user.getFailedAttempt() + 1;
        userRepository.findById(user.getId()).ifPresent(u -> {
            u.setFailedAttempt(newFailedAttempts);
            userRepository.save(u);
        });
    }

    @Transactional
    public void resetFailedAttempts(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            user.setFailedAttempt(0);
            userRepository.save(user);
        });
    }

    @Transactional
    public void lockUser(User user) {
        user.setAccountNonLocked(false);
        user.setLockTime(LocalDateTime.now());
        userRepository.save(user);
    }

    @Transactional
    public boolean unlockWhenTimeExpired(User user) {
        if (user.getLockTime() != null) {
            LocalDateTime lockTime = user.getLockTime();
            LocalDateTime unlockTime = lockTime.plusHours(24);
            
            if (LocalDateTime.now().isAfter(unlockTime)) {
                user.setAccountNonLocked(true);
                user.setLockTime(null);
                user.setFailedAttempt(0);
                userRepository.save(user);
                return true;
            }
        }
        return false;
    }
}