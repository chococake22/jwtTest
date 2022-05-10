package com.test.jwtTest.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;

import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;


@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        // 내 서버가 응답을 할 때 json을 자바스크립트에서 처리할 수 있도록 설정하는 것
        config.setAllowCredentials(true);

        // 모든 ip에 응답을 허용함
        config.addAllowedOrigin("*");

        // 모든 header에 응답을 허용함
        config.addAllowedHeader("*");

        // 모든 Post, Get, Put, Delete, Patch 요청을 허용함
        config.addAllowedMethod("*");   // 모든 요청에서 다 허용

        // 저장된 주소로 들어오는 모든 요청은 config 설정을 따른다.
        source.registerCorsConfiguration("/api/**", config);

        return new CorsFilter(source);
    }


}
