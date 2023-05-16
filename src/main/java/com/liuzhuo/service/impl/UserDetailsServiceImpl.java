package com.liuzhuo.service.impl;

import com.liuzhuo.domain.Permission;
import com.liuzhuo.domain.SecurityUser;
import com.liuzhuo.domain.User;
import com.liuzhuo.service.PermissionService;
import com.liuzhuo.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import javax.annotation.Resource;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {
    @Resource
    private UserService userService;

    @Resource
    private PermissionService permissionService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 查询用户
        User user = userService.findByUsername(username);
        if (ObjectUtils.isEmpty(user)) {
            throw new UsernameNotFoundException("用户或密码不正确!");
        }

        // 组装SecurityUser
        SecurityUser userDetail = new SecurityUser();
        BeanUtils.copyProperties(user, userDetail);

        // 获取用户的权限
        List<Permission> permissionList = permissionService.findPermissionListByUserId(user.getId());

        // 设置用户权限
        userDetail.setPermissions(permissionList);

        // 过滤掉code为null的权限，并且将code转换为字符串数组
        String[] strings = permissionList.stream().map(Permission::getCode).filter(Objects::nonNull).toArray(String[]::new);

        // 生成权限列表
        List<GrantedAuthority> authorityList = AuthorityUtils.createAuthorityList(strings);
        userDetail.setAuthorities(authorityList);

        return userDetail;
    }
}
