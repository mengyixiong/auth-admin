package com.liuzhuo.common.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.liuzhuo.common.exception.CustomerAuthenticationException;
import com.liuzhuo.common.vo.ResultVo;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
public class LoginFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        // 设置客户端的响应编码
        response.setContentType("application/json;charset=utf-8");

        // 获取错误信息
        Integer code = 500;
        String message;
        //判断异常类型
        if (exception instanceof AccountExpiredException) {
            message = "账户过期,登录失败！";
        } else if (exception instanceof BadCredentialsException) {
            message = "用户名或密码错误,登录失败！";
        } else if (exception instanceof CredentialsExpiredException) {
            message = "密码过期,登录失败！";
        } else if (exception instanceof DisabledException) {
            message = "账户被禁用,登录失败！";
        } else if (exception instanceof LockedException) {
            message = "账户被锁,登录失败！";
        } else if (exception instanceof InternalAuthenticationServiceException) {
            message = "账户不存在,登录失败！";
        } else if (exception instanceof CustomerAuthenticationException) {
            message = exception.getMessage();
            code = 600;
        } else {
            message = "登录失败！";
        }

        // 转成json
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(ResultVo.error(code, message));

        // 响应给客户端
//        response.getWriter().print(json);
//        response.getWriter().flush();
//        response.getWriter().close();
        ServletOutputStream outputStream = response.getOutputStream();
        outputStream.write(json.getBytes(StandardCharsets.UTF_8));
        outputStream.flush();
        outputStream.close();
    }
}
