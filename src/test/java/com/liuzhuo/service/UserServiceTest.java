package com.liuzhuo.service;

import com.liuzhuo.common.constant.PublicConstant;
import com.liuzhuo.common.exception.ApiException;
import com.liuzhuo.common.utils.RedisUtil;
import com.liuzhuo.common.vo.UserInfoVo;
import com.liuzhuo.domain.Permission;
import com.liuzhuo.domain.SecurityUser;
import com.liuzhuo.domain.User;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.util.ObjectUtils;

import javax.annotation.Resource;
import java.util.List;

@SpringBootTest
public class UserServiceTest {

    @Resource
    private RedisUtil redisUtil;

    @Resource
    private PermissionService permissionService;

    @Test
    public void testGetInfo() {
//        User user = (User) redisUtil.hmGet(PublicConstant.USER_INFO_KEY, "admin");
//        List<Permission> permissions = permissionService.findPermissionListByUserId(user.getId());
//
//
//        //获取角色权限编码字段
//        Object[] roles = permissions.stream().map(Permission::getCode).toArray();
//
//
//        System.out.println(new UserInfoVo(user.getId(),user.getNickName(),user.getAvatar(),null,roles));
    }

}
