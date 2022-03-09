package hello.springsecurity.service.impl;

import hello.springsecurity.domain.Account;
import hello.springsecurity.repository.UserRepository;
import hello.springsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service("userService")
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;

	@Transactional
	@Override
	public void createUser(Account account) {
		userRepository.save(account);
	}
}
