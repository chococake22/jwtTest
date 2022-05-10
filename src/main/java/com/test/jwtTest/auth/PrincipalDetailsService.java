package com.test.jwtTest.auth;

import com.test.jwtTest.model.User;
import com.test.jwtTest.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.awt.print.Pageable;

// http://localhost:8080/login => formlogin을 disabled로 했기 때문에 동작을 안한다.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService의 loadUserByUsername 실행");
        System.out.println(username);
        User userEntity = userRepository.findByUsername(username);
        System.out.println("userEntity : " + userEntity);
        return new PrincipalDetails(userEntity);
    }

    public ResponseEntity test1(String username) {

        if (userRepository.findByUsername(username) == null) {
            // throw new UsernameNotFoundException("이미 존재하는 아이디입니다.");
            //return new ResponseEntity(new User(), HttpStatus.BAD_REQUEST);
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        Pageable pageable = (Pageable) PageRequest.of(0, 20, Sort.Direction.DESC);

        return new ResponseEntity<>(new User(), HttpStatus.OK);
    }
}
