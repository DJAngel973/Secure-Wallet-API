package com.wallet.secure.user.service;

import com.wallet.secure.common.enums.UserRole;
import com.wallet.secure.config.AdminBootstrapProperties;
import com.wallet.secure.user.entity.User;
import com.wallet.secure.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AdminBootstrapServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private AdminBootstrapProperties properties;
    private AdminBootstrapService service;

    @BeforeEach
    void setUp() {
        properties = new AdminBootstrapProperties();
        service = new AdminBootstrapService(properties, userRepository, passwordEncoder);
    }

    @Test
    void disabledBootstrapDoesNotQueryOrCreateUser() throws Exception {
        service.run(new DefaultApplicationArguments());

        verifyNoInteractions(userRepository, passwordEncoder);
    }

    @Test
    void validBootstrapCreatesVerifiedAdminWithEncodedPassword() throws Exception {
        properties.setEnabled(true);
        properties.setEmail("admin@example.test");
        properties.setPassword("StrongPass1!");
        when(userRepository.existsByRole(UserRole.ADMIN)).thenReturn(false);
        when(userRepository.existsByEmail("admin@example.test")).thenReturn(false);
        when(passwordEncoder.encode("StrongPass1!")).thenReturn("$2a$12$encoded");

        service.run(new DefaultApplicationArguments());

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();
        assertThat(saved.getRole()).isEqualTo(UserRole.ADMIN);
        assertThat(saved.getEmail()).isEqualTo("admin@example.test");
        assertThat(saved.getPasswordHash()).isEqualTo("$2a$12$encoded");
        assertThat(saved.getEmailVerified()).isTrue();
        verify(passwordEncoder).encode("StrongPass1!");
    }

    @Test
    void existingAdminPreventsSecondAdmin() throws Exception {
        properties.setEnabled(true);
        properties.setEmail("admin@example.test");
        properties.setPassword("StrongPass1!");
        when(userRepository.existsByRole(UserRole.ADMIN)).thenReturn(true);

        service.run(new DefaultApplicationArguments());

        verify(userRepository, never()).save(any(User.class));
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void invalidPasswordFailsWithoutPersistingOrLoggingSecret() {
        properties.setEnabled(true);
        properties.setEmail("admin@example.test");
        properties.setPassword("short");

        assertThatThrownBy(() -> service.run(new DefaultApplicationArguments()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Admin bootstrap password does not meet minimum requirements");
        verifyNoInteractions(userRepository, passwordEncoder);
    }
}
