package com.websocket.chat.config;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Web Security 설정
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
				.csrf().disable() // 기본값이 on인 csrf 취약점 보안을 해제한다. on으로 설정해도 되나 설정할경우 웹페이지에서 추가처리가 필요함.
				.headers()
				.frameOptions().sameOrigin() // SockJS는 기본적으로 HTML iframe 요소를 통한 전송을 허용하지 않도록 설정되는데 해당 내용을 해제한다.
				.and()
				.formLogin() // 권한없이 페이지 접근하면 로그인 페이지로 이동한다.
				.and()
				.authorizeRequests()
				.antMatchers("/chat/**").hasRole("USER") // chat으로 시작하는 리소스에 대한 접근 권한 설정
				.anyRequest().permitAll(); // 나머지 리소스에 대한 접근 설정
		return http.build();
	}

	@Bean
	public UserDetailsManager users(DataSource dataSource) {
		JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

		UserDetails user = User.withUsername("happydaddy")
				.password(encoder.encode("1234"))
				.roles("USER")
				.build();
		users.createUser(user);

		user = User.withUsername("angrydaddy")
				.password(encoder.encode("1234"))
				.roles("USER")
				.build();
		users.createUser(user);

		user = User.withUsername("guest")
				.password(encoder.encode("1234"))
				.roles("USER")
				.build();
		users.createUser(user);

		return users;
	}

}
