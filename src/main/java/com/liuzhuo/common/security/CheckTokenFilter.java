package com.liuzhuo.common.security;

import com.liuzhuo.common.constant.PublicConstant;
import com.liuzhuo.common.exception.CustomerAuthenticationException;
import com.liuzhuo.common.utils.JwtUtils;
import com.liuzhuo.common.utils.RedisUtil;
import com.liuzhuo.service.impl.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CheckTokenFilter extends OncePerRequestFilter {

    @Resource
    private JwtUtils jwtUtils;

    @Resource
    private UserDetailsServiceImpl userDetailsService;

    @Resource
    private LoginFailureHandler loginFailureHandler;

    @Resource
    private RedisUtil redisUtil;

    //获取登录请求地址
    @Value("${request.login.url}")
    private String loginUrl;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 获取当前的请求URI
        String requestURI = request.getRequestURI();

        // 如果不是登录请求，需要验证token
        if (!requestURI.equals(this.loginUrl)) {
            try {
                this.validateToken(request);
                filterChain.doFilter(request, response);
            } catch (AuthenticationException e) {
                loginFailureHandler.onAuthenticationFailure(request, response, e);
            }
        } else {
            filterChain.doFilter(request, response);
        }



    }

    /**
     * 验证token
     */
    public void validateToken(HttpServletRequest request) throws AuthenticationException {
        String token = request.getHeader(PublicConstant.TOKEN_HEADER);

        // 如果请求头里面没有则抛出异常
        if (ObjectUtils.isEmpty(token)) {
            throw new CustomerAuthenticationException("身份信息不存在,请登录!");
        }

        // 定义tokenKey
        String tokenKey = "token_" + token;
        String redisToken = redisUtil.get(tokenKey);

        // 如果redis中没有则抛出异常
        if (ObjectUtils.isEmpty(redisToken)) {
            throw new CustomerAuthenticationException("身份信息已过期");
        }

        // 如果值不一样也要抛出异常
        if (!redisToken.equals(token)) {
            throw new CustomerAuthenticationException("身份信息不正确");
        }

        // 判断token是否过期
        if (jwtUtils.isTokenExpired(token)) {
            throw new CustomerAuthenticationException("身份信息已过期");
        }

        // 解析token
        String username = jwtUtils.getUsernameFromToken(token);
        if (ObjectUtils.isEmpty(username)) {
            throw new CustomerAuthenticationException("身份信息解析失败");
        }

        // 查询用户信息
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (ObjectUtils.isEmpty(userDetails)) {
            throw new CustomerAuthenticationException("用户信息验证失败");
        }

        //创建身份验证对象
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );

        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }
}
