package com.example.demo.config;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.security.KeyStore;

/**
 * @author : Mamadou Cherif KASSE
 * @version : 1.0
 * @email : mamadoucherifkasse@gmail.com
 * @created : 30/05/2025, vendredi
 */
public class SslRestTemplateFactory {
    public static RestTemplate createRestTemplateWithClientCert() throws Exception {
        // Charger le fichier P12
        char[] password = "password".toCharArray(); // Remplace par le vrai mot de passe
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        // Lecture depuis resources
        ClassPathResource classPathResource = new ClassPathResource("LocalTest.p12");
        try (InputStream inputStream = classPathResource.getInputStream()) {
            keyStore.load(inputStream, password);
        }

        // Créer le SSLContext
        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(keyStore, password) // le certificat client
                .build();

        // Appliquer le SSLContext au RestTemplate
        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);
        CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(socketFactory)
                .build();

        HttpComponentsClientHttpRequestFactory requestFactory =
                new HttpComponentsClientHttpRequestFactory(httpClient);

        return new RestTemplate(requestFactory);
    }
}
