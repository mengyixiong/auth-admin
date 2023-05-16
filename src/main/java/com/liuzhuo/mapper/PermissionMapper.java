package com.liuzhuo.mapper;

import com.liuzhuo.domain.Permission;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

import java.util.List;

/**
* @author Administrator
* @description 针对表【sys_permission】的数据库操作Mapper
* @createDate 2023-05-16 14:43:47
* @Entity com.liuzhuo.domain.Permission
*/
public interface PermissionMapper extends BaseMapper<Permission> {

    /**
     * 根据用户ID查询权限列表
     * @param userId
     * @return
     */
    List<Permission> findPermissionListByUserId(Long userId);
}




