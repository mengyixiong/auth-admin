package com.liuzhuo.service;

import com.liuzhuo.domain.Permission;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;

/**
* @author Administrator
* @description 针对表【sys_permission】的数据库操作Service
* @createDate 2023-05-16 14:43:47
*/
public interface PermissionService extends IService<Permission> {
    /**
     * 根据用户ID查询权限列表
     * @param userId
     * @return
     */
    List<Permission> findPermissionListByUserId(Long userId);
}
