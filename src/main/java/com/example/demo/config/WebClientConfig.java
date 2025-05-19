package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author : Mamadou Cherif KASSE
 * @version : 1.0
 * @email : mamadoucherifkasse@gmail.com
 * @created : 08/05/2025, jeudi
 */
@Configuration
public class WebClientConfig {
    @Bean
    public WebClient webClient() {
        return WebClient.builder().build();
    }
}
