package com.liuzhuo.mapper;

import com.liuzhuo.domain.Permission;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;
import java.util.List;
import java.util.stream.Collectors;

@SpringBootTest
public class PermissionMapperTest {

    @Resource
    private PermissionMapper permissionMapper;

    @Test
    public void test() {
        List<Permission> permissionList = permissionMapper.findPermissionListByUserId(1L);
        List<String> permissionStrings = permissionList.stream().filter(item-> item.getCode() != null).map(Permission::getCode).collect(Collectors.toList());
        permissionStrings.forEach(System.out::println);
    }

}
