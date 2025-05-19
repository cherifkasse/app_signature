package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.cache.annotation.EnableCaching;


@SpringBootApplication
@EnableCaching
public class AppSignatureApplication extends SpringBootServletInitializer {

	public static void main(String[] args) {
		SpringApplication.run(AppSignatureApplication.class, args);
	}

	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder builder){
		return builder.sources(AppSignatureApplication.class);
	}

}
