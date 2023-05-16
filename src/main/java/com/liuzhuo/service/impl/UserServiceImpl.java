package com.liuzhuo.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.liuzhuo.common.constant.PublicConstant;
import com.liuzhuo.common.exception.ApiException;
import com.liuzhuo.common.utils.JwtUtils;
import com.liuzhuo.common.utils.RedisUtil;
import com.liuzhuo.common.vo.UserInfoVo;
import com.liuzhuo.domain.Permission;
import com.liuzhuo.domain.SecurityUser;
import com.liuzhuo.domain.User;
import com.liuzhuo.service.UserService;
import com.liuzhuo.mapper.UserMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Administrator
 * @description 针对表【sys_user】的数据库操作Service实现
 * @createDate 2023-05-16 14:43:47
 */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User>
        implements UserService {

    @Resource
    private JwtUtils jwtUtils;

    @Resource
    private RedisUtil redisUtil;

    @Resource
    private AuthenticationManager authenticationManager;

    @Override
    public User findByUsername(String username) {
        // 组装查询条件
        LambdaQueryWrapper<User> where = new LambdaQueryWrapper<>();
        where.eq(User::getUsername, username);

        // 查询并返回
        return this.getOne(where);
    }

    @Override
    public HashMap<String, Object> refreshToken(String token) {
         // 刷新token
        String newToken = jwtUtils.refreshToken(token);

        // 获取新token的过期时间
        long expireTime = jwtUtils.getExpirationFromToken(token).getTime();

        // 删除redis里面的token
        redisUtil.delete("token_" + token);

        // 将新token添加导redis里面
        redisUtil.set("token_" + newToken, newToken, jwtUtils.getExpiration() / 1000);

        // 组装返回数据
        HashMap<String, Object> data = new HashMap<>();
        data.put("token", newToken);
        data.put("expireTime", expireTime);

        return data;
    }

    @Override
    public UserInfoVo getInfo() {
        //从Spring Security上下文获取用户信息
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();
        if (ObjectUtils.isEmpty(authentication)){
            throw new ApiException("用户信息查询失败");
        }

        // 获取spring security框架的用户详情
        SecurityUser principal = (SecurityUser) authentication.getPrincipal();

        // 在redis中获取数据库中的用户详情
        User user = (User) redisUtil.hmGet(PublicConstant.USER_INFO_KEY, principal.getUsername());
        if (ObjectUtils.isEmpty(user)){
            throw new ApiException("用户信息查询失败");
        }

        // 获取用户的权限
        List<Permission> permissions = principal.getPermissions();

        //获取角色权限编码字段
        Object[] roles = permissions.stream().map(Permission::getCode).toArray();

        return new UserInfoVo(user.getId(),user.getNickName(),user.getAvatar(),null,roles);
    }

    @Override
    public Map<String, Object> login(String username, String password) {
        // 用户验证
        Authentication authentication = null;
        // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username,password));
        } catch (AuthenticationException e) {
            if (e instanceof BadCredentialsException) {
                throw new ApiException("用户不存在或密码错误");
            }
            throw new ApiException(e.getMessage());
        }
        SecurityUser loginUser = (SecurityUser) authentication.getPrincipal();

        // 生成token
        String token = jwtUtils.generateToken(loginUser);

        // 获取过期时间
        long expireTime = jwtUtils.getExpirationFromToken(token).getTime();

        // 组装返回数据
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("expireTime", expireTime);

        // 查询用户信息存储到redis中
        User sysUser = this.findByUsername(loginUser.getUsername());

        // 存入redis
        redisUtil.set("token_" + token,token, jwtUtils.getExpiration() / 1000);

        // 将用户信息存入redis
        redisUtil.hmSet(PublicConstant.USER_INFO_KEY,loginUser.getUsername(),sysUser);

        //更新最后登录信息
//        systemAdmin.setLoginCount(systemAdmin.getLoginCount() + 1);
//        systemAdmin.setLastIp(ip);

        return data;
    }
}




