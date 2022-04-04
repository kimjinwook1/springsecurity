package hello.springsecurity.security.config;

import hello.springsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import hello.springsecurity.security.filter.AjaxLoginProcessingFilter;
import hello.springsecurity.security.handler.AjaxAccessDeniedHandler;
import hello.springsecurity.security.handler.AjaxAuthenticationFailureHandler;
import hello.springsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import hello.springsecurity.security.provider.AjaxAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(ajaxAuthenticationProvider());
	}

	@Bean
	public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
		return new AjaxAuthenticationSuccessHandler();
	}

	@Bean
	public AuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
		return new AjaxAuthenticationFailureHandler();
	}

	@Bean
	public AuthenticationProvider ajaxAuthenticationProvider() {
		return new AjaxAuthenticationProvider();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.antMatcher("/api/**")
			.authorizeRequests()
			.antMatchers("/api/messages").hasRole("MANAGER")
			.anyRequest().authenticated()
			.and()
			.addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
		http
			.exceptionHandling()
			.authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())//로그인 하지 않고 특정 url에 접근할 경우 (인가예외)
			.accessDeniedHandler(ajaxAccessDeniedHandler());// ROLE 관련해서 차단

		http.csrf().disable();

		customConfigurerAjax(http);

	}

	private void customConfigurerAjax(HttpSecurity http) throws Exception {
		http.
			apply(new AjaxLoginConfigurer<>())
			.successHandlerAjax(ajaxAuthenticationSuccessHandler())
			.failureHandlerAjax(ajaxAuthenticationFailureHandler())
			.setAuthenticationManager(authenticationManagerBean())
			.loginProcessingUrl("/api/login");
	}

	@Bean
	public AccessDeniedHandler ajaxAccessDeniedHandler() {
		return new AjaxAccessDeniedHandler();
	}

	@Bean
	public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
		AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
		ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
		ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
		ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
		return ajaxLoginProcessingFilter;
	}

}
//
//<!DOCTYPE html>
//<html xmlns:th="http://www.thymeleaf.org">
//
//<meta id="_csrf" name="_csrf" th:content="${_csrf.token}"/>
//<meta id="_csrf_header" name="_csrf_header" th:content="${_csrf.headerName}"/>
//
//<head th:replace="layout/header::userHead"></head>
//<script>
//    function formLogin(e) {
//
//		var username = $("input[name='username']").val().trim();
//		var password = $("input[name='password']").val().trim();
//		var data = {"username" : username, "password" : password};
//
//		var csrfHeader = $('meta[name="_csrf_header"]').attr('content')
//		var csrfToken = $('meta[name="_csrf"]').attr('content')
//
//		$.ajax({
//		type: "post",
//		url: "/api/login",
//		data: JSON.stringify(data),
//		dataType: "json",
//		beforeSend : function(xhr){
//		xhr.setRequestHeader(csrfHeader, csrfToken);
//		xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
//		xhr.setRequestHeader("Content-type","application/json");
//		},
//		success: function (data) {
//		console.log(data);
//		window.location = '/';
//		},
//		error : function(xhr, status, error) {
//		console.log(error);
//		window.location = '/login?error=true&exception=' + xhr.responseText;
//		}
//		});
//		}
//
//
//<!DOCTYPE html>
//<html lang="ko" xmlns:th="http://www.thymeleaf.org">
//<head th:replace="layout/header::userHead"></head>
//<html xmlns:th="http://www.thymeleaf.org">
//
//<meta id="_csrf" name="_csrf" th:content="${_csrf.token}"/>
//<meta id="_csrf_header" name="_csrf_header" th:content="${_csrf.headerName}"/>
//
//<head th:replace="layout/header::userHead"></head>
//<script>
//    function messages() {
//
//		var csrfHeader = $('meta[name="_csrf_header"]').attr('content')
//		var csrfToken = $('meta[name="_csrf"]').attr('content')
//
//		$.ajax({
//		type: "post",
//		url: "/api/messages",
//		//dataType: "json",
//		beforeSend : function(xhr){
//		xhr.setRequestHeader(csrfHeader, csrfToken);
//		xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
//		xhr.setRequestHeader("Content-type","application/json");
//		},
//		success: function (data) {
//		console.log(data);
//		window.location = '/messages';
//		},
//		error : function(xhr, status, error) {
//		console.log(error);
//		if(xhr.responseJSON.status == '401'){
//		window.location = '/api/login?error=true&exception=' + xhr.responseJSON.message;
//		}else if(xhr.responseJSON.status == '403'){
//		window.location = '/api/denied?exception=' + xhr.responseJSON.message;
//		}
//		}
//		});
//		}
