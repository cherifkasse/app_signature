package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

/**
 * @author : Mamadou Cherif KASSE
 * @version : 1.0
 * @email : mamadoucherifkasse@gmail.com
 * @created : 06/05/2025, mardi
 */
@Configuration
public class RestTemplateConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
