package com.liuzhuo.common.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.liuzhuo.common.constant.PublicConstant;
import com.liuzhuo.common.constant.ResultCode;
import com.liuzhuo.common.utils.JwtUtils;
import com.liuzhuo.common.utils.RedisUtil;
import com.liuzhuo.common.vo.LoginResult;
import com.liuzhuo.common.vo.ResultVo;
import com.liuzhuo.domain.SecurityUser;
import com.liuzhuo.domain.User;
import com.liuzhuo.service.UserService;
import io.jsonwebtoken.Jwts;
import jdk.nashorn.internal.ir.ReturnNode;
import org.apache.ibatis.util.MapUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import javax.security.auth.login.AccountExpiredException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Resource
    private JwtUtils jwtUtils;

    @Resource
    private RedisUtil redisUtil;

    @Resource
    private UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 设置客户端的响应编码
        response.setContentType("application/json;charset=utf-8");

        // 获取当前用户信息
        SecurityUser user = (SecurityUser) authentication.getPrincipal();

        // 生成TOKEN
        String token = jwtUtils.generateToken(user);

        // 获取过期时间
        long expireTime = jwtUtils.getExpirationFromToken(token).getTime();

        // 组装返回数据
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("expireTime", expireTime);

        // 查询用户信息存储到redis中
        User sysUser = userService.findByUsername(user.getUsername());

        // 存入redis
        redisUtil.set("token_" + token,token, jwtUtils.getExpiration() / 1000);

        // 将用户信息存入redis
        redisUtil.hmSet(PublicConstant.USER_INFO_KEY,user.getUsername(),sysUser);

        // 转成json字符串
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(ResultVo.success("登录成功", data));

        // 响应给客户端
        response.getWriter().print(json);
        response.getWriter().flush();
        response.getWriter().close();
    }
}
