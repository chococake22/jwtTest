package com.test.jwtTest.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.test.jwtTest.auth.PrincipalDetails;
import com.test.jwtTest.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// login 요청해서 username, password를 전송하면
// UsernamePasswordAuthenticationFilter가 동작을 한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;  // 얘를 이용해서 로그인을 진행한다

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        System.out.println("JwtAuthenticationFilter : 로그인 시도");

        // 1. username, password 받아서
        try {
//            BufferedReader br = request.getReader();    // request를 읽을 수 있도록 한다.
//
//            String input = null;
//            while ((input = br.readLine()) != null) {
//                System.out.println(input);
//            }

            // ObjectMapper가 Json을 파싱한다.
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 이게 실행될 때 PrincipalDetailsService의 loadUserByUsername() 함수가 실행된다. -> 얘는 username만 받는다 / password는 스프링에서 알아서 DB를 이용해서 처리 해줌
            Authentication authentication = // <- 여기에 내가 로그인한 정보가 담긴다.
                    authenticationManager.authenticate(authenticationToken);
            // 토큰을 통해 로그인 시도를 해서 성공하면 authentication를 만든다
            // PrincicpalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨

           // authentication 객체가 session 영역에 저장된다는 것 => 로그인이 되었다는 증거
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

            // 값 확인
            System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername());

            System.out.println("1========================================");

            // authentication 객체가 session 영역에 저장된다. (리턴으로 저장하는 것이다)
            // 리턴을 하는 이유는 권한 관리를 Security가 대신 해주기 때문에 편하려고 하는 것
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없다. -> 단지 권한처리때문에 session을 넣어줍니다.

            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("2========================================");

        // 2. 정상인지 로그인 시도를 해보는 것.
        // authenticationManager로 로그인 시도를 하면
        // PrincipalDetailsService의 loadUserByUsername()함수 호출

        // 3. PrincipalDetails를 세션에 담고(권한 관리를 위해서 담는다) / 세션에 담는 이유는 권한 관리가 안된다

        // 4. JWT 토큰을 만들어서 응답하면 된다.

        // 오류가 나면 null 리턴
        return null;
    }


    // attemptAuthentication 메서드 실행 후 인증이 정상적으로 되었을 경우 successfulAuthentication 메서드가 실행
    // JWT 토큰을 만들어서 request요청한 사용자에게 JWT 토큰을 response 해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // 토큰 생성하기
        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))    // 토큰이 언제까지 유요할지 만료시간 지정(좀 짧게 줘야 다른 사람한테 탈취가 되지 않는다)
                                            // 현재시간 + 10분
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));    // 내 서버만 아는 고유한 값(서명하는 것) -> cos

        response.addHeader("Authorization", "Bearer " + jwtToken);

    }
}
