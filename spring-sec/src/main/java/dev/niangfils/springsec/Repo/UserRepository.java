package dev.niangfils.springsec.Repo;

import dev.niangfils.springsec.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findUserByUsername(String username);
}
