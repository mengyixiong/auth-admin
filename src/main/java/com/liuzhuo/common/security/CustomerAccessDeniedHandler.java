package com.liuzhuo.common.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.liuzhuo.common.vo.ResultVo;
import com.liuzhuo.domain.SecurityUser;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 身份已经验证，但是没有权限访问资源的处理器
 */
@Component
public class CustomerAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        // 设置客户端的响应编码
        response.setContentType("application/json;charset=utf-8");

        // 转成json字符串
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(ResultVo.error(403,"没有权限访问此资源，请联系管理员" ));

        // 响应给客户端
        response.getWriter().print(json);
        response.getWriter().flush();
        response.getWriter().close();
    }
}
