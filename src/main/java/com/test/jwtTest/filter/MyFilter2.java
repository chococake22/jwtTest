package com.test.jwtTest.filter;


import javax.servlet.*;
import java.io.IOException;

public class MyFilter2 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("필터2");

        // Filter chain에 등록
        chain.doFilter(request, response);
    }
}
