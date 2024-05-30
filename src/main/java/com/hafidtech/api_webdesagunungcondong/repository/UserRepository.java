package com.hafidtech.api_webdesagunungcondong.repository;

import com.hafidtech.api_webdesagunungcondong.entities.Role;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    User findByRole(Role role);
}
