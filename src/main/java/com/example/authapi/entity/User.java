package com.example.authapi.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String name;

    private String phone;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserType userType;

    private boolean enabled = false;

    private boolean accountNonLocked = true;

    private int failedAttempt = 0;

    private LocalDateTime lockTime;

    @Column(unique = true)
    private String verificationToken;

    private LocalDateTime verificationTokenExpiry;

    private String resetPasswordToken;

    private LocalDateTime resetPasswordTokenExpiry;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public void generateVerificationToken() {
        this.verificationToken = UUID.randomUUID().toString();
        this.verificationTokenExpiry = LocalDateTime.now().plusDays(1);
    }

    public void generateResetPasswordToken() {
        this.resetPasswordToken = UUID.randomUUID().toString();
        this.resetPasswordTokenExpiry = LocalDateTime.now().plusHours(1);
    }

    public boolean isVerificationTokenValid() {
        return verificationTokenExpiry != null && LocalDateTime.now().isBefore(verificationTokenExpiry);
    }

    public boolean isResetPasswordTokenValid() {
        return resetPasswordTokenExpiry != null && LocalDateTime.now().isBefore(resetPasswordTokenExpiry);
    }
}