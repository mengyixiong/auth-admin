package com.liuzhuo.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.liuzhuo.domain.Department;
import com.liuzhuo.service.DepartmentService;
import com.liuzhuo.mapper.DepartmentMapper;
import org.springframework.stereotype.Service;

/**
* @author Administrator
* @description 针对表【sys_department】的数据库操作Service实现
* @createDate 2023-05-16 14:43:47
*/
@Service
public class DepartmentServiceImpl extends ServiceImpl<DepartmentMapper, Department>
    implements DepartmentService{

}




