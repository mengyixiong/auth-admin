package com.liuzhuo.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.liuzhuo.domain.Role;
import com.liuzhuo.service.RoleService;
import com.liuzhuo.mapper.RoleMapper;
import org.springframework.stereotype.Service;

/**
* @author Administrator
* @description 针对表【sys_role】的数据库操作Service实现
* @createDate 2023-05-16 14:43:47
*/
@Service
public class RoleServiceImpl extends ServiceImpl<RoleMapper, Role>
    implements RoleService{

}




