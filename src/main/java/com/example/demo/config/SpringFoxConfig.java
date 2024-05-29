package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

@Configuration
@EnableWebMvc
public class SpringFoxConfig implements WebMvcConfigurer {

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2).select()
                .apis(RequestHandlerSelectors.basePackage("com.example.demo"))
                .paths(PathSelectors.regex("/.*"))
                .build().apiInfo(apiInfoMetaData())
                .useDefaultResponseMessages(false);
    }

    private ApiInfo apiInfoMetaData() {

        return new ApiInfoBuilder().title("Documentation API REST serveur de signature")
                .description("Dans cette documentation, nous vous guiderons à travers chaque aspect de l'API, en fournissant des exemples concrets, des descriptions détaillées des endpoints et des meilleures pratiques pour une intégration efficace. Que vous soyez un développeur expérimenté ou que vous découvriez l'intégration d'une signature électronique pour la première fois, notre objectif est de vous fournir les outils et les ressources nécessaires pour réussir.")
                .contact(new Contact("Orbus Digital Services", "https://www.ods.sn/", "contact@ods.sn"))
                .version("1.0.0")
                .build();
    }

}