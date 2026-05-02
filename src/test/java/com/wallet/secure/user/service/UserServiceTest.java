package com.wallet.secure.user.service;

import com.wallet.secure.audit.service.AuditService;
import com.wallet.secure.common.exception.EmailAlreadyExistsException;
import com.wallet.secure.common.exception.InvalidCredentialsException;
import com.wallet.secure.common.exception.UnauthorizedOperationException;
import com.wallet.secure.common.exception.UserNotFoundException;
import com.wallet.secure.common.response.ApiResponse;
import com.wallet.secure.common.enums.UserRole;
import com.wallet.secure.user.dto.RegisterRequest;
import com.wallet.secure.user.dto.UpdateProfileRequest;
import com.wallet.secure.user.dto.UserResponse;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for UserService.
 *
 * WHY unit tests (not integration):
 * - No Spring context → runs in milliseconds
 * - No DB → completely isolated
 * - Mocks replace real dependencies → test only the business logic
 *
 * @ExtendWith(MockitoExtension.class) → enables Mockito in JUnit 5
 * @Mock → creates a fake object (no real DB or BCrypt calls)
 * @InjectMocks → creates UserService injecting the mocks above
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserService Unit Tests")
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuditService auditService;

    @InjectMocks
    private UserService userService;

    // ─── Shared test data ─────────────────────────────────────────────────────

    private User testUser;
    private UUID testUserId;

    @BeforeEach
    void setUp() {
        testUserId = UUID.randomUUID();
        testUser = User.builder()
                .email("pedro@test.com")
                .passwordHash("$2a$12$hashedPassword")
                .role(UserRole.USER)
                .build();
        // Simulate DB-generated ID
        testUser.setId(testUserId);
    }

    // ─── register() ───────────────────────────────────────────────────────────

    @Nested
    @DisplayName("register()")
    class RegisterTests {

        /**
         * Happy path — email available, password gets hashed, user saved.
         * Verifies: BCrypt is called, entity is saved, response has correct data.
         */
        @Test
        @DisplayName("Should register user successfully when email is available")
        void shouldRegisterUserSuccessfully() {
            // ARRANGE — prepare inputs and mock behavior
            RegisterRequest request = new RegisterRequest();
            setField(request, "email", "pedro@test.com");
            setField(request, "password", "SecurePass12!");

            when(userRepository.existsByEmail("pedro@test.com")).thenReturn(false);
            when(passwordEncoder.encode("SecurePass12!")).thenReturn("$2a$12$hashed");
            when(userRepository.save(any(User.class))).thenReturn(testUser);

            // ACT — call the method under test
            ApiResponse<UserResponse> response = userService.register(request);

            // ASSERT — verify the result
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getMessage()).isEqualTo("User registered successfully");
            assertThat(response.getData().getEmail()).isEqualTo("pedro@test.com");
            assertThat(response.getData().getRole()).isEqualTo(UserRole.USER);

            // Verify BCrypt was called — password must be hashed
            verify(passwordEncoder).encode("SecurePass12!");
            // Verify user was saved to DB
            verify(userRepository).save(any(User.class));
        }

        /**
         * Email already taken → EmailAlreadyExistsException.
         * OWASP A07: message should not reveal if email exists.
         */
        @Test
        @DisplayName("Should throw EmailAlreadyExistsException when email is taken")
        void shouldThrowWhenEmailAlreadyExists() {
            // ARRANGE
            RegisterRequest request = new RegisterRequest();
            setField(request, "email", "existing@test.com");
            setField(request, "password", "SecurePass12!");

            when(userRepository.existsByEmail("existing@test.com")).thenReturn(true);

            // ACT & ASSERT — expect the exception
            assertThatThrownBy(() -> userService.register(request))
                    .isInstanceOf(EmailAlreadyExistsException.class)
                    .hasMessage("Email already in use");

            // Verify BCrypt was NEVER called — fail fast before hashing
            verify(passwordEncoder, never()).encode(anyString());
            // Verify save was NEVER called
            verify(userRepository, never()).save(any());
        }
    }

    // ─── getProfile() ─────────────────────────────────────────────────────────

    @Nested
    @DisplayName("getProfile()")
    class GetProfileTests {

        @Test
        @DisplayName("Should return profile when user exists")
        void shouldReturnProfileWhenUserExists() {
            // ARRANGE
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));

            // ACT
            ApiResponse<UserResponse> response = userService.getProfile(testUserId);

            // ASSERT
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData().getEmail()).isEqualTo("pedro@test.com");
            // OWASP A02: sensitive fields must NOT be in UserResponse
            // UserResponse doesn't have passwordHash — compile-time check
        }

        @Test
        @DisplayName("Should throw UserNotFoundException when user does not exist")
        void shouldThrowWhenUserNotFound() {
            // ARRANGE
            UUID nonExistentId = UUID.randomUUID();
            when(userRepository.findById(nonExistentId)).thenReturn(Optional.empty());

            // ACT & ASSERT
            assertThatThrownBy(() -> userService.getProfile(nonExistentId))
                    .isInstanceOf(UserNotFoundException.class)
                    .hasMessage("User not found");
        }

        @Test
        @DisplayName("Should return profile even when account is deactivated")
        void shouldReturnProfileOfDeactivatedAccount() {
            // ARRANGE — usuario con isActive = false
            User deactivatedUser = User.builder()
                    .email("inactive@test.com")
                    .passwordHash("$2a$12$hash")
                    .role(UserRole.USER)
                    .build();
            deactivatedUser.setId(testUserId);
            deactivatedUser.setIsActive(false);  // ← cuenta desactivada

            when(userRepository.findById(testUserId))
                    .thenReturn(Optional.of(deactivatedUser));

            // ACT
            ApiResponse<UserResponse> response = userService.getProfile(testUserId);

            // ASSERT
            // UserService devuelve el perfil — el Controller decide si mostrarlo
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getData().getIsActive()).isFalse();  // ← visible en respuesta
        }

        @Test
        @DisplayName("Should return deactivated status in UserResponse")
        void shouldExposeDeactivatedStatusInResponse() {
            // ARRANGE
            testUser.setIsActive(false);
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));

            // ACT
            ApiResponse<UserResponse> response = userService.getProfile(testUserId);

            // ASSERT — isActive=false se refleja en el DTO (no se oculta)
            assertThat(response.getData().getIsActive()).isFalse();
        }
    }

    // ─── updateProfile() ──────────────────────────────────────────────────────

    @Nested
    @DisplayName("updateProfile()")
    class UpdateProfileTests {

        @Test
        @DisplayName("Should update password successfully with correct current password")
        void shouldUpdatePasswordSuccessfully() {
            // ARRANGE
            UpdateProfileRequest request = new UpdateProfileRequest();
            setField(request, "currentPassword", "OldPass12!");
            setField(request, "password", "NewPass12!");

            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("OldPass12!", "$2a$12$hashedPassword"))
                    .thenReturn(true);
            when(passwordEncoder.matches("NewPass12!", "$2a$12$hashedPassword"))
                    .thenReturn(false);
            when(passwordEncoder.encode("NewPass12!")).thenReturn("$2a$12$newHash");
            when(userRepository.save(any(User.class))).thenReturn(testUser);

            // ACT
            ApiResponse<UserResponse> response = userService.updateProfile(testUserId, request);

            // ASSERT
            assertThat(response.isSuccess()).isTrue();
            verify(passwordEncoder).encode("NewPass12!");
            verify(userRepository).save(any(User.class));
            // OWASP A09: password change MUST generate an audit log entry
            verify(auditService).logPasswordChange(eq(testUserId), anyString(), isNull(), isNull());
        }

        @Test
        @DisplayName("Should throw InvalidCredentialsException when current password is wrong")
        void shouldThrowWhenCurrentPasswordIsWrong() {
            // ARRANGE
            UpdateProfileRequest request = new UpdateProfileRequest();
            setField(request, "currentPassword", "WrongPass12!");
            setField(request, "password", "NewPass12!");

            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("WrongPass12!", "$2a$12$hashedPassword"))
                    .thenReturn(false);

            // ACT & ASSERT
            assertThatThrownBy(() -> userService.updateProfile(testUserId, request))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessage("Current password is incorrect");

            // New password must NEVER be encoded if current is wrong
            verify(passwordEncoder, never()).encode(anyString());
        }

        @Test
        @DisplayName("Should throw when new password is same as current")
        void shouldThrowWhenNewPasswordSameAsCurrent() {
            // ARRANGE
            UpdateProfileRequest request = new UpdateProfileRequest();
            setField(request, "currentPassword", "SamePass12!");
            setField(request, "password", "SamePass12!");

            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("SamePass12!", "$2a$12$hashedPassword"))
                    .thenReturn(true) // current password OK
                    .thenReturn(true); // new == current

            // ACT & ASSERT
            assertThatThrownBy(() -> userService.updateProfile(testUserId, request))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessage("New password must be different from current password");
        }
    }

    // ─── deactivateAccount() ──────────────────────────────────────────────────

    @Nested
    @DisplayName("deactivateAccount()")
    class DeactivateTests {

        @Test
        @DisplayName("Should deactivate own account successfully")
        void shouldDeactivateOwnAccount() {
            // GIVEN — user deactivates themselves (userId == requesterId)
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(userRepository.save(any(User.class))).thenReturn(testUser);

            // WHEN
            ApiResponse<Void> response = userService.deactivateAccount(testUserId, testUserId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            verify(userRepository).save(argThat(u -> !u.getIsActive()));
            // OWASP A09: deactivation is a critical event — must be audited
            verify(auditService).logCriticalSecurityEvent(eq(testUserId), anyString(), isNull(), isNull());
        }

        @Test
        @DisplayName("Should allow ADMIN to deactivate another user")
        void shouldAllowAdminToDeactivateAnotherUser() {
            // GIVEN — admin (different UUID) deactivates target user
            UUID adminId = UUID.randomUUID();
            User adminUser = User.builder()
                    .email("admin@test.com")
                    .passwordHash("$2a$12$adminHash")
                    .role(UserRole.ADMIN)
                    .build();
            adminUser.setId(adminId);

            // findById is called twice: once for the target, once for the requester
            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(userRepository.findById(adminId)).thenReturn(Optional.of(adminUser));
            when(userRepository.save(any(User.class))).thenReturn(testUser);

            // WHEN
            ApiResponse<Void> response = userService.deactivateAccount(testUserId, adminId);

            // THEN
            assertThat(response.isSuccess()).isTrue();
            verify(userRepository).save(argThat(u -> !u.getIsActive()));
            verify(auditService).logCriticalSecurityEvent(eq(testUserId), anyString(), isNull(), isNull());
        }

        @Test
        @DisplayName("Should throw UnauthorizedOperationException when non-ADMIN tries to deactivate another user")
        void shouldThrowWhenNonAdminTriesToDeactivateAnotherUser() {
            // GIVEN — a regular USER tries to deactivate someone else's account
            UUID intruderId = UUID.randomUUID();
            User intruder = User.builder()
                    .email("intruder@test.com")
                    .passwordHash("$2a$12$hash")
                    .role(UserRole.USER)
                    .build();
            intruder.setId(intruderId);

            when(userRepository.findById(testUserId)).thenReturn(Optional.of(testUser));
            when(userRepository.findById(intruderId)).thenReturn(Optional.of(intruder));

            // WHEN / THEN
            assertThatThrownBy(() -> userService.deactivateAccount(testUserId, intruderId))
                    .isInstanceOf(UnauthorizedOperationException.class);

            // Account must NOT have been deactivated
            verify(userRepository, never()).save(any());
            // No audit log for a blocked attempt
            verify(auditService, never()).logCriticalSecurityEvent(any(), any(), any(), any());
        }
    }

    // ─── Test helper ──────────────────────────────────────────────────────────

    /**
     * Sets a private field via reflection — needed because DTOs use
     * private fields with no setters (Lombok @Getter only).
     * Only used in tests — never in production code.
     */
    private void setField(Object target, String fieldName, Object value) {
        try {
            var field = target.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set field: " + fieldName, e);
        }
    }
}
