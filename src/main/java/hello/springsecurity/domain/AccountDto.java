package hello.springsecurity.domain;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AccountDto {

	private String username;
	private String password;
	private String email;
	private String age;
	private String role;

	public AccountDto(Account account) {
		this.username = account.getUsername();
		this.password = account.getPassword();
		this.age = account.getAge();
		this.email = account.getEmail();
		this.role = account.getRole();
	}

}
