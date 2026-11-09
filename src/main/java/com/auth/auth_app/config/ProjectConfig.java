package com.auth.auth_app.config;

import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Controller;

@Configuration
public class ProjectConfig {

    @Bean
    public ModelMapper modelMapper(){
        return new ModelMapper();
    }
}
