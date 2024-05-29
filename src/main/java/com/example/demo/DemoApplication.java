package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication
public class DemoApplication extends SpringBootServletInitializer {

	public static void main(String[] args) {

		SpringApplication.run(DemoApplication.class, args);
	}
	protected SpringApplicationBuilder configure(SpringApplicationBuilder builder){
		return builder.sources(DemoApplication.class);
	}

}
