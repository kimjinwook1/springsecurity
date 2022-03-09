package hello.springsecurity.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import lombok.Data;

@Data
@Entity
public class Account {

	@Id
	@GeneratedValue
	@Column(name = "account_id")
	private Long id;
	private String username;
	private String password;
	private String email;
	private String age;
	private String role;
}
