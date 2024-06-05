package com.hafidtech.api_webdesagunungcondong.repository;

import com.hafidtech.api_webdesagunungcondong.entities.Role;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
@Transactional(readOnly = true)
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    Optional<User> findByEmailAndIsEnabled(String email, boolean isEnabled);

    Optional<User> findIdByEmail(String email);

//    @Modifying
//    @Query("SELECT u.email, u.password FROM User u WHERE u.email = ?1 AND u.password = ?2")
//    void findUsernameAndPassword(String email, String password);

    User findByEmailAndPassword(String email, String password);

    User findByRole(Role role);


}
