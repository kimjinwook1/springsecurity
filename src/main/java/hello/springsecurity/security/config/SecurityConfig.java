package hello.springsecurity.security.config;

import hello.springsecurity.oauth.CustomOAuth2UserService;
import hello.springsecurity.security.common.FormAuthenticationDetailsSource;
import hello.springsecurity.security.handler.CustomAccessDeniedHandler;
import hello.springsecurity.security.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final UserDetailsService userDetailsService;
	private final FormAuthenticationDetailsSource authenticationDetailsSource;
	private final AuthenticationSuccessHandler customAuthenticationSuccessHandler;
	private final AuthenticationFailureHandler customAuthenticationFailureHandler;
	private final CustomOAuth2UserService customOAuth2UserService;


	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		String password = passwordEncoder().encode("1111");
//		auth.inMemoryAuthentication().withUser("user").password(password).roles("USER"); -> 메모리 인증 방식
//		auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER","USER");
//		auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN","MANAGER","USER");

//		auth.userDetailsService(userDetailsService);
		auth.authenticationProvider(authenticationProvider());
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
		//정적 파일들이 보안필터를 거치지 않고 통과처리
	}

	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.antMatchers("/", "/users", "user/login/**", "/login*").permitAll()
			.antMatchers("/mypage").hasRole("USER")
			.antMatchers("/messages").hasRole("MANAGER")
			.antMatchers("/config").hasRole("ADMIN")
			.anyRequest().authenticated()
			.and()
			.formLogin()
			.loginPage("/login")
			.loginProcessingUrl("/login_proc")
			.authenticationDetailsSource(authenticationDetailsSource)
			.defaultSuccessUrl("/")
			.successHandler(customAuthenticationSuccessHandler)
			.failureHandler(customAuthenticationFailureHandler)
			.permitAll()
			.and()
			.exceptionHandling()
			.accessDeniedHandler(accessDeniedHandler())
			.and()
			.oauth2Login()
			.loginPage("/login")
			.defaultSuccessUrl("/")
			.failureUrl("/login")
			.userInfoEndpoint()
			.userService(customOAuth2UserService);



		//	.and()
		//			.oauth2Login()
		//			.userInfoEndpoint()
		//			.userService(customOAuth2UserService);
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		return new CustomAuthenticationProvider();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
		accessDeniedHandler.setErrorPage("/denied");
		return accessDeniedHandler;
	}
}
