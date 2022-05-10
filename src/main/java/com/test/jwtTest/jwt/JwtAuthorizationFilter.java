package com.test.jwtTest.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.test.jwtTest.auth.PrincipalDetails;
import com.test.jwtTest.model.User;
import com.test.jwtTest.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter라는 것이 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있다.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 타지 않는다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;

    }


    // 인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터를 타게 된다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // super.doFilterInternal(request, response, chain);    // 응답을 한번만 해야하기 때문에 여기서는 지운다
        System.out.println("인증이나 권한이 필요한 주소 요청이 됨");

        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader : " + jwtHeader);


        // header가 있는지 확인
        // jwtHeader가 비어있거나 Bearer로 시작하는 게 아니라면 다시 필터를 타도록 함(인증이나 권한이 필요없는 요청이기 때문에)
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");
        String username =
                JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();   // 토큰에 서명함


        System.out.println("username : " + username );
        // 서명이 정상적으로 됨
        if (username != null) {

            System.out.println("username 정상");
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            // authentication 객체 강제로 만들기
            // Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null,  principalDetails.getAuthorities());

            // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }

        chain.doFilter(request, response);
    }
}
