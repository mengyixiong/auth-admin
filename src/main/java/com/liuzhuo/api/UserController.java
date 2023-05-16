package com.liuzhuo.api;

import com.liuzhuo.common.constant.PublicConstant;
import com.liuzhuo.common.utils.MenuTree;
import com.liuzhuo.common.vo.ResultVo;
import com.liuzhuo.common.vo.RouterVo;
import com.liuzhuo.domain.Permission;
import com.liuzhuo.domain.SecurityUser;
import com.liuzhuo.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/user")
public class UserController {
    @Resource
    private UserService userService;

    @PostMapping("/login")
    public ResultVo login(String username, String password) {
        return ResultVo.success(userService.login(username,password));
    }

    /**
     * 刷新token
     */
    @PostMapping("/refreshToken")
    public ResultVo refreshToken(HttpServletRequest request) {
        String token = request.getHeader(PublicConstant.TOKEN_HEADER);
        return ResultVo.success("刷新成功", userService.refreshToken(token));
    }

    /**
     * 查询所有用户列表
     *
     * @return
     */
    @GetMapping("/list")
    public ResultVo list() {
        return ResultVo.success("查询成功", userService.list());
    }

    /**
     * 用户信息
     */
    @GetMapping("/info")
    public ResultVo getInfo() {
        return ResultVo.success(userService.getInfo());
    }

    /**
     * 获取菜单数据
     *
     * @return
     */
    @GetMapping("/getMenuList")
    public ResultVo getMenuList() {
        //从Spring Security上下文获取用户信息
        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        //获取用户信息
        SecurityUser user = (SecurityUser) authentication.getPrincipal();

        //获取相应的权限
        List<Permission> permissionList = user.getPermissions();

        //筛选目录和菜单
        List<Permission> collect = permissionList.stream()
                .filter(item -> item != null && item.getType() != 2)
                .collect(Collectors.toList());

        //生成路由数据
        List<RouterVo> routerVoList = MenuTree.makeRouter(collect, 0L);

        //返回数据
        return ResultVo.success("菜单数据获取成功", routerVoList);
    }
}