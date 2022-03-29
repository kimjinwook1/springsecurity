package hello.springsecurity.repository;

import hello.springsecurity.domain.Account;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {
	Account findByUsername(String username);

	Optional<Account> findByEmail(String email);
}
