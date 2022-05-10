package com.test.jwtTest.config;

import com.test.jwtTest.jwt.JwtAuthenticationFilter;
import com.test.jwtTest.jwt.JwtAuthorizationFilter;
import com.test.jwtTest.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 시큐리티 필터 체인에 걸어주는 것 -> 직접 필터를 만드는 것으로 변경(BasicAuthenticationFilter 이전에 MyFilter1이 실행된다)
        // http.addFilterBefore(new MyFilter1(), BasicAuthenticationFilter.class);

        // Security가 동작하기 전에 실행하는 filter 등록(SecurityContextPersistenceFilter 이전에 MyFilter3가 실행된다)
        // http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);

       // csrf 사용 안하기
        http.csrf().disable();
        // 세션을 사용하지 않고 stateless 상태로 만든다
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsFilter)  // 설정한 필터를 등록함(모든 요청을 다 허용하도록 filter에서 설정함)
                .formLogin().disable()
                .httpBasic().disable() // 기본 httpBasic 방식이 아닌 bearer 방식을 사용할 것이다.
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))   // AuthenticationManager를 넘겨야 한다.
                            // 로그인 요청시 attemptAuthentication 메서드 실행
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER')")
                .anyRequest().permitAll();


    }
}
