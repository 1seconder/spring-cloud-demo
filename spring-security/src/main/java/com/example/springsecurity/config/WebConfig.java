package com.example.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
//        WebMvcConfigurer.super.addViewControllers(registry);

        //实现无业务逻辑的 页面跳转  输入 / 跳转到login.html
        registry.addViewController("/aa").setViewName("index");
//        registry.addViewController("/").setViewName("login");
        registry.addViewController("/bb").setViewName("index");
        registry.addViewController("/").setViewName("redirect:/login_view");
        registry.addViewController("/login_view").setViewName("login");

    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
//        WebMvcConfigurer.super.addInterceptors(registry);
    }
}
