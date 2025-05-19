package com.example.demo.service;

import com.example.demo.model.Signataire;
import com.example.demo.model.Signataire_V2;
import com.example.demo.model.Worker;
import com.github.benmanes.caffeine.cache.AsyncCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.cache.CacheMono;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Signal;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * @author : Mamadou Cherif KASSE
 * @version : 1.0
 * @email : mamadoucherifkasse@gmail.com
 * @created : 06/05/2025, mardi
 */
@Service
public class CacheService {

    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private WebClient webClient;

    @Autowired
    private AsyncCache<Integer, Signataire> signataireCache;

    @Autowired
    private AsyncCache<Integer, Signataire_V2> signataireV2Cache;

    @Autowired
    private AsyncCache<Integer, Worker> workerCache;

    @Autowired
    private AsyncCache<Integer, Boolean> workerExistsCache;

    @Autowired
    private AsyncCache<String, List<Worker>> workerCacheNom;

    @Value("${url_access}")
    private String urlAccessBdd;



//    @Cacheable(value = "signataireV2Cache", key = "#idSigner")
//    public Signataire_V2 getSignataireV2(Integer idSigner) {
//        String url = urlAccessBdd + "findSignerById/" + idSigner;         .
//        return restTemplate.getForObject(url, Signataire_V2.class);
//    }
//    @Cacheable(value = "workerExistenceCache", key = "#idWorker")
//    public boolean isWorkerExists(Integer idWorker) {
//        String url = urlAccessBdd + "isExistedWorker/" + idWorker;
//        return Boolean.TRUE.equals(restTemplate.getForObject(url, Boolean.class));
//    }

//    @Cacheable(value = "workerCache", key = "#idWorker")
//    public Worker getWorker(Integer idWorker) {
//        String url = urlAccessBdd + "findNomWorkerById/" + idWorker;
//        return restTemplate.getForObject(url, Worker.class);
//    }
//    @Cacheable(value = "signataireCache", key = "#idSigner")
//    public Signataire getSignataire(Integer idSigner) {
//        String url = urlAccessBdd + "findSignataireById/" + idSigner;
//        return restTemplate.getForObject(url, Signataire.class);
//    }

    public Mono<Signataire_V2> getSignataireV2(Integer id) {
        return CacheMono.lookup(k ->
                                // Charger depuis le cache si présent
                                Mono.fromFuture(() -> signataireV2Cache.get(k, key -> {
                                            // Récupérer la donnée du cache, si présente
                                            return null; // Retourner null si la valeur n'est pas présente dans le cache
                                        }))
                                        .map(o -> Signal.next((Signataire_V2) o)), // Cast de l'objet récupéré en Signataire_V2

                        id
                )
                .onCacheMissResume(() -> {
                    // Si la valeur n'est pas trouvée dans le cache, effectuez une requête via WebClient
                    return webClient.get()
                            .uri(urlAccessBdd + "findSignerById/{id}", id) // Appel HTTP avec le paramètre id
                            .retrieve()
                            .bodyToMono(Signataire_V2.class) // Récupérer la réponse en tant que Mono<Signataire_V2>
                            ;
                })
                .andWriteWith((k, signal) -> {
                    Signataire_V2 valeur = signal.get();
                    signataireV2Cache.put(k, CompletableFuture.completedFuture(valeur));
                    return Mono.empty();
                })
                .onErrorResume(e -> {
                    // Gestion des erreurs, renvoie une valeur par défaut ou une exception
                    return Mono.error(new RuntimeException("Erreur lors de la récupération de Signataire_V2", e));
                });
    }




    public Mono<Signataire> getSignataire(Integer id) {
        return CacheMono.lookup(k ->
                                Mono.fromFuture(() -> signataireCache.get(k, key -> null))
                                        .map(o -> Signal.next((Signataire) o)), // ✅ bien enveloppé dans un Signal
                        id
                )
                .onCacheMissResume(() ->
                        webClient.get()
                                .uri(urlAccessBdd + "findSignataireById/{id}", id)
                                .retrieve()
                                .bodyToMono(Signataire.class)
                )
                .andWriteWith((k, signal) -> {
                    // ✅ extraction propre depuis le Signal
                    Signataire valeur = signal.get();
                    signataireCache.put(k, CompletableFuture.completedFuture(valeur));
                    return Mono.empty();
                })
                .onErrorResume(e ->
                        Mono.error(new RuntimeException("Erreur lors de la récupération de Signataire", e))
                );
    }



    public Mono<Boolean> isWorkerExists(Integer id) {
        return CacheMono.lookup(k ->
                                Mono.fromFuture(() -> workerExistsCache.get(k, key -> null))
                                        .map(o -> Signal.next((Boolean) o)),
                        id
                )
                .onCacheMissResume(() ->
                        webClient.get()
                                .uri(urlAccessBdd + "isExistedWorker/{id}", id)
                                .retrieve()
                                .bodyToMono(Boolean.class)
                )
                .andWriteWith((k, v) -> {
                    Boolean value = v.get();
                    workerExistsCache.put(k, CompletableFuture.completedFuture(value));
                    return Mono.empty();
                })
                .onErrorResume(e ->
                        Mono.error(new RuntimeException("Erreur lors de la vérification de l'existence du Worker", e))
                );
    }




    public Mono<Worker> getWorker(Integer id) {
        return CacheMono.lookup(k ->
                                Mono.fromFuture(() -> workerCache.get(k, key -> null))
                                        .map(o -> Signal.next((Worker) o)), // ✅ envelopper dans un Signal
                        id
                )
                .onCacheMissResume(() ->
                        webClient.get()
                                .uri(urlAccessBdd + "findNomWorkerById/{id}", id)
                                .retrieve()
                                .bodyToMono(Worker.class)
                )
                .andWriteWith((k, signal) -> {
                    // ✅ extraire proprement l’objet Worker depuis le Signal
                    Worker valeur = signal.get();
                    workerCache.put(k, CompletableFuture.completedFuture(valeur));
                    return Mono.empty();
                })
                .onErrorResume(e ->
                        Mono.error(new RuntimeException("Erreur lors de la récupération du Worker", e))
                );
    }

    public Mono<List<Worker>> getWorkersByNom(String nomWorker) {
        return CacheMono.lookup(k ->
                                Mono.fromFuture(() -> workerCacheNom.get(k, key -> null))
                                        .map(o -> Signal.next((List<Worker>) o)),
                        nomWorker
                )
                .onCacheMissResume(() ->
                        webClient.get()
                                .uri(uriBuilder -> uriBuilder
                                        .path(urlAccessBdd + "getWorkerByNom")
                                        .queryParam("nomWorker", nomWorker)
                                        .build()
                                )
                                .retrieve()
                                .bodyToFlux(Worker.class)
                                .collectList()
                )
                .andWriteWith((k, signal) -> {
                    List<Worker> workers = signal.get();
                    if (workers != null) {
                        workerCacheNom.put(k, CompletableFuture.completedFuture(workers));
                    }
                    return Mono.empty();
                })
                .onErrorResume(e ->
                        Mono.error(new RuntimeException("Erreur lors de la récupération des Workers", e))
                );
    }



}
