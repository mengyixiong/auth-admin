package com.liuzhuo.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.liuzhuo.common.exception.ApiException;
import com.liuzhuo.common.utils.JwtUtils;
import com.liuzhuo.common.utils.RedisUtil;
import com.liuzhuo.domain.SecurityUser;
import com.liuzhuo.domain.User;
import com.liuzhuo.service.UserService;
import com.liuzhuo.mapper.UserMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import javax.annotation.Resource;
import java.util.HashMap;

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
}




