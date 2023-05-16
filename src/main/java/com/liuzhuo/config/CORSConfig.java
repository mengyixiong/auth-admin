package com.liuzhuo.config;

import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

public class CORSConfig implements WebMvcConfigurer {
     @Override
     public void addCorsMappings(CorsRegistry registry) {
         registry.addMapping("/**") // 允许所有的请求访问
                 .allowedOrigins("*")  // 允许所有的请求域名访问我们的跨域资源，可以固定单个或者多个域名
                 .allowedMethods("*")  // 允许所有的请求方法访问该跨域资源服务器，如：POST、GET、PUT、DELETE等。
                 .allowedHeaders("*"); // 允许所有的请求header访问
     }
}
