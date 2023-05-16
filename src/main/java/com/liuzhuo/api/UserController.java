package com.liuzhuo.api;

import com.liuzhuo.common.constant.PublicConstant;
import com.liuzhuo.common.vo.ResultVo;
import com.liuzhuo.service.UserService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/user")
public class UserController {
    @Resource
    private UserService userService;

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
}