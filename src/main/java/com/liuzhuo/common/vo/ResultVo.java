package com.liuzhuo.common.vo;

import lombok.Data;

@Data
public class ResultVo<T> {
    private Integer code;
    private String msg;
    private T data;

    /**
     * 不准实例化
     */
    private ResultVo() {
    }

    public static <T> ResultVo<T> success() {
        ResultVo<T> resultVo = new ResultVo<>();
        resultVo.setCode(200);
        resultVo.setMsg("操作成功");
        resultVo.setData(null);
        return resultVo;
    }

    public static <T> ResultVo<T> success(T data) {
        ResultVo<T> resultVo = new ResultVo<>();
        resultVo.setCode(200);
        resultVo.setMsg("操作成功");
        resultVo.setData(data);
        return resultVo;
    }

    public static <T> ResultVo<T> success(String msg) {
        ResultVo<T> resultVo = new ResultVo<>();
        resultVo.setCode(200);
        resultVo.setMsg(msg);
        resultVo.setData(null);
        return resultVo;
    }

    public static <T> ResultVo<T> success(String msg, T data) {
        ResultVo<T> resultVo = new ResultVo<>();
        resultVo.setCode(200);
        resultVo.setMsg(msg);
        resultVo.setData(data);
        return resultVo;
    }

    public static <T> ResultVo<T> error(Integer code, String msg) {
        ResultVo<T> resultVo = new ResultVo<>();
        resultVo.setCode(code);
        resultVo.setMsg(msg);
        resultVo.setData(null);
        return resultVo;
    }

    public static <T> ResultVo<T> error(Integer code) {
        ResultVo<T> resultVo = new ResultVo<>();
        resultVo.setCode(code);
        resultVo.setMsg("执行失败");
        resultVo.setData(null);
        return resultVo;
    }

    public static <T> ResultVo<T> error(String msg) {
        ResultVo<T> resultVo = new ResultVo<>();
        resultVo.setCode(500);
        resultVo.setMsg(msg);
        resultVo.setData(null);
        return resultVo;
    }
}
