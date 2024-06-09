package com.hafidtech.api_webdesagunungcondong.repository;

import com.hafidtech.api_webdesagunungcondong.entities.Role;
import com.hafidtech.api_webdesagunungcondong.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
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
    
    

    Optional<User> findByEmailAndPassword(String email, String password);

    User findByRole(Role role);

//    ResponseEntity<User> updateById(User user, Long id);


    @Modifying
    @Query(value = "UPDATE User u SET u.email=:email1, u.file=:file1, u.fileName=:fileName1, u.firstName=:firstName1, u.lastName=:lastName1, u.password=:password1, u.role=:role1, u.type=:type1, u.uploadDir=:uploadDir1 where u.id=:id1")

    void update(Long id1, String firstName1, String lastName1, String email1, String password1, String fileName1, Role role1, byte[] file1, String type1, String uploadDir1);


    User findFileNameById(Long id);
}
