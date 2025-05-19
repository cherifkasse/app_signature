package com.example.demo.config;

import com.example.demo.model.Signataire;
import com.example.demo.model.Signataire_V2;
import com.example.demo.model.Worker;
import com.github.benmanes.caffeine.cache.AsyncCache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * @author : Mamadou Cherif KASSE
 * @version : 1.0
 * @email : mamadoucherifkasse@gmail.com
 * @created : 08/05/2025, jeudi
 */
@Configuration
public class CacheConfig {
    @Bean
    public AsyncCache<Integer, Signataire_V2> signataireV2Cache() {
        return Caffeine.newBuilder()
                .expireAfterWrite(24, TimeUnit.HOURS)
                .maximumSize(1000)
                .buildAsync();
    }

    @Bean
    public AsyncCache<String, List<Worker>> workerCacheNom() {
        return Caffeine.newBuilder()
                .expireAfterWrite(24, TimeUnit.HOURS)
                .maximumSize(1000)
                .buildAsync();
    }


    @Bean
    public AsyncCache<Integer, Signataire> signataireCache() {
        return Caffeine.newBuilder()
                .expireAfterWrite(24, TimeUnit.HOURS)
                .maximumSize(1000)
                .buildAsync();
    }

    @Bean
    public AsyncCache<Integer, Worker> workerCache() {
        return Caffeine.newBuilder()
                .expireAfterWrite(24, TimeUnit.HOURS)
                .maximumSize(1000)
                .buildAsync();
    }

    @Bean
    public AsyncCache<Integer, Boolean> workerExistsCache() {
        return Caffeine.newBuilder()
                .expireAfterWrite(24, TimeUnit.HOURS)
                .maximumSize(1000)
                .buildAsync();
    }

    @Bean
    public AsyncCache<Integer, Boolean> cache() {
        return Caffeine.newBuilder()
                .expireAfterWrite(24, TimeUnit.HOURS)
                .maximumSize(1000)
                .buildAsync();
    }

}
