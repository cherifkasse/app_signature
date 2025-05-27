package com.example.demo.config;

/**
 * @author Cherif KASSE
 * @project SunuBtrust360_Enrol
 * @created 24/11/2023/11/2023 - 11:25
 */

import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.security.KeyStore;
import java.util.Properties;

public class CustomHttpRequestFactory {
    Properties prop = null;
    Logger log = null;
    public CustomHttpRequestFactory() {
        log = LogManager.getLogger(CustomHttpRequestFactory.class);
        log.debug("Registration class constructor");
        try (InputStream input = CustomHttpRequestFactory.class.getClassLoader().getResourceAsStream("configWin.properties")) {

            prop = new Properties();

            if (input == null) {
                System.out.println("Sorry, unable to find config.properties");
                return;
            }
            //load a properties file from class path, inside static method
            prop.load(input);
            log.debug("Registration class constructor: prop.loaded");


            log.debug("Registration class constructor: Identifier_lApplication()");

        } catch (IOException ex) {
            ex.printStackTrace();
            log.error(ex);
        }
    }
    private CredentialsProvider getCredentialsProvider(String username, String password) {
        CredentialsProvider provider = new BasicCredentialsProvider();
        provider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));
        return provider;
    }

    public ClientHttpRequestFactory getClientHttpRequestFactory(String username, String password) {
        try {
            // Charger le keystore
            SSLContext sslContext = SSLContextBuilder
                    .create()
                    .loadKeyMaterial(loadKeyStore(), prop.getProperty("password_keystore").toCharArray())
                    .loadTrustMaterial(loadTrustStore(), (TrustStrategy) TrustSelfSignedStrategy.INSTANCE)
                    .build();

            // Créer un client HTTP avec la configuration SSL personnalisée et l'autorisation
            CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLContext(sslContext)
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .setDefaultCredentialsProvider(getCredentialsProvider(username, password))
                    .build();

            // Utiliser une usine de requêtes personnalisée avec le client HTTP
            return new SimpleClientHttpRequestFactory() {
                @Override
                protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                    if (connection instanceof HttpsURLConnection) {
                        ((HttpsURLConnection) connection).setSSLSocketFactory(sslContext.getSocketFactory());
                    }
                    super.prepareConnection(connection, httpMethod);
                }
            };
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

        public  ClientHttpRequestFactory getClientHttpRequestFactory() {
        try {
            // Charger le keystore
            SSLContext sslContext = SSLContextBuilder
                    .create()
                    .loadKeyMaterial(loadKeyStore(), prop.getProperty("password_keystore").toCharArray())
                    .loadTrustMaterial(loadTrustStore(), (TrustStrategy) TrustSelfSignedStrategy.INSTANCE)
                    .build();

            // Créer un client HTTP avec la configuration SSL personnalisée
            CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLContext(sslContext)
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build();

            // Utiliser une usine de requêtes personnalisée avec le client HTTP
            return new SimpleClientHttpRequestFactory() {
                @Override
                protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
                    if (connection instanceof HttpsURLConnection) {
                        ((HttpsURLConnection) connection).setSSLSocketFactory(sslContext.getSocketFactory());
                    }
                    super.prepareConnection(connection, httpMethod);
                }
            };
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public  KeyStore loadKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream keystoreInputStream = new FileInputStream(prop.getProperty("keystore"))) {
            keyStore.load(keystoreInputStream, prop.getProperty("password_keystore").toCharArray());

        }
        catch (Exception e) {
            e.printStackTrace();
            System.err.println("Erreur lors de la création de l'usine de requêtes personnalisée : " + e.getMessage());
            return null;
        }
        return keyStore;
    }

    public  KeyStore loadTrustStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream keystoreInputStream = new FileInputStream(prop.getProperty("trustore1"))) {
            keyStore.load(keystoreInputStream, prop.getProperty("password_keystore").toCharArray());
        }
        catch (Exception e) {
            e.printStackTrace();
            System.err.println("Erreur lors de la création de l'usine de requêtes personnalisée : " + e.getMessage());
            return null;
        }
        return keyStore;
    }
}
