package com.liuzhuo.service;

import com.liuzhuo.domain.User;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.HashMap;

/**
 * @author Administrator
 * @description 针对表【sys_user】的数据库操作Service
 * @createDate 2023-05-16 14:43:47
 */
public interface UserService extends IService<User> {
    /**
     * 根据用户名获取用户信息
     * @param username
     * @return
     */
    User findByUsername(String username);

    /**
     * 刷新用户token
     * @param token
     * @return
     */
    HashMap<String,Object> refreshToken(String token);
}
