package com.liuzhuo.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.liuzhuo.domain.Permission;
import com.liuzhuo.service.PermissionService;
import com.liuzhuo.mapper.PermissionMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
* @author Administrator
* @description 针对表【sys_permission】的数据库操作Service实现
* @createDate 2023-05-16 14:43:47
*/
@Service
public class PermissionServiceImpl extends ServiceImpl<PermissionMapper, Permission>
    implements PermissionService{

    @Resource
    private PermissionMapper permissionMapper;

    @Override
    public List<Permission> findPermissionListByUserId(Long userId) {
        return permissionMapper.findPermissionListByUserId(userId);
    }
}




