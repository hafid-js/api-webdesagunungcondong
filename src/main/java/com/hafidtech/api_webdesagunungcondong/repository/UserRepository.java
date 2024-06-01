package com.hafidtech.api_webdesagunungcondong.repository;

import com.hafidtech.api_webdesagunungcondong.entities.Role;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
@Transactional(readOnly = true)
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    Optional<User> findByEmailAndIsEnabled(String email, boolean isEnabled);

    User findByRole(Role role);


}
