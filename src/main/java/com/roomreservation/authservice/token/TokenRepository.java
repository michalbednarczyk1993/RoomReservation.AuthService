package com.roomreservation.authservice.token;

import com.roomreservation.authservice.user.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<TokenEntity, Integer> {

    @Query(value = """
            select t from Token t \s
            inner join User u on t.user.id = u.id where \s
            u.id = :id and (t.expired = false and t.revoked = false) \s
            """)
    List<TokenEntity> findAllValidTokensByUser(Integer id);

    Optional<TokenEntity> findByToken(String token);

    UserEntity

}
