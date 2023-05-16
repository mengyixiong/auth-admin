package com.liuzhuo.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.liuzhuo.domain.UserRole;
import com.liuzhuo.service.UserRoleService;
import com.liuzhuo.mapper.UserRoleMapper;
import org.springframework.stereotype.Service;

/**
* @author Administrator
* @description 针对表【sys_user_role】的数据库操作Service实现
* @createDate 2023-05-16 14:43:47
*/
@Service
public class UserRoleServiceImpl extends ServiceImpl<UserRoleMapper, UserRole>
    implements UserRoleService{

}




