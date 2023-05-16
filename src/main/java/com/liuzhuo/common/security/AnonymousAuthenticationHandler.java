package com.liuzhuo.common.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.liuzhuo.common.vo.ResultVo;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 当用户没有登录访问受限资源时返回的处理器
 */
@Component
public class AnonymousAuthenticationHandler implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // 设置客户端的响应编码
        response.setContentType("application/json;charset=utf-8");

        // 转成json字符串
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(ResultVo.error(401,"请登录"));

        // 响应给客户端
        response.getWriter().print(json);
        response.getWriter().flush();
        response.getWriter().close();
    }
}
