package com.liuzhuo.common.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserInfoVo {
    private Long id;//用户ID
    private String name;//用户名称
    private String avatar;//头像
    private String introduction;//介绍
    private Object[] roles;//角色权限集合
}
