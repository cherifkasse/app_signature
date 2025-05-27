package com.example.demo.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * @author : Mamadou Cherif KASSE
 * @version : 1.0
 * @email : mamadoucherifkasse@gmail.com
 * @created : 23/05/2025, vendredi
 */
@RestController
@RequestMapping("/testCharge")
public class TestChargeController {
    @Value("${urlBaseTestCharge}")
    private String urlBaseTestCharge;

    @Value("${nombreToursTest}")
    private String nombreTours;


    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper mapper = new ObjectMapper();
    Random random = new Random();
    String[] prenoms = {"Mame", "Cheikh", "Awa", "Fatou", "Seynabou", "Aliou", "Diop", "Ndiaye"};
    String[] noms = {"Sarr", "Ba", "Fall", "Diagne", "Ndoye", "Camara", "Sow", "Faye"};

    @PostMapping("/run")
    public ResponseEntity<?> runSimulation() throws Exception {
        long startGlobal = System.currentTimeMillis();

        Random random = new Random();

        int nbreTours = Integer.parseInt(nombreTours);
        for (int i = 0; i < nbreTours; i++) {
            long stepStart, stepEnd;

            try {
                // -------- ENROLL --------
                System.out.println(">> Début ENROLL [" + i + "]");
                stepStart = System.currentTimeMillis();
                long debutEnrol = stepStart;
                String nomSignataire = prenoms[random.nextInt(prenoms.length)] + " " +
                        noms[random.nextInt(noms.length)] + " " + random.nextInt(1000);

                String cni = String.valueOf(1000000000L + Math.abs(random.nextLong()) % 9000000000L);

                Map<String, Object> payload = new HashMap<>();
                payload.put("nomSignataire", nomSignataire);
                payload.put("cni", cni);
                payload.put("telephone", "+221778680" + i);
                payload.put("idApplication", 17);

                HttpHeaders jsonHeaders = new HttpHeaders();
                jsonHeaders.setContentType(MediaType.APPLICATION_JSON);
                HttpEntity<Map<String, Object>> enrollRequest = new HttpEntity<>(payload, jsonHeaders);

//                ResponseEntity<String> enrollResponseTest = restTemplate.getForEntity(urlBaseTestCharge, String.class);
//                System.out.println("Sortie api test: "+enrollResponseTest.getBody());
                String urlEnrol = urlBaseTestCharge+"enroll";
                ResponseEntity<String> enrollResponse = restTemplate.postForEntity(
                        urlEnrol , enrollRequest, String.class);


                if (!enrollResponse.getStatusCode().is2xxSuccessful()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Erreur ENROLL : " + enrollResponse.getBody());
                }

                JsonNode enrollResult = mapper.readTree(enrollResponse.getBody());
                int idSignataire = enrollResult.get("id_signer").asInt();
                String codePin = enrollResult.get("codePin").asText();

                stepEnd = System.currentTimeMillis();
                System.out.println("<< Fin ENROLL [" + i + "] - Durée: " + (stepEnd - stepStart) + " ms");

                // -------- DEPOT --------
                System.out.println(">> Début DEPOT [" + i + "]");
                stepStart = System.currentTimeMillis();

                MultiValueMap<String, Object> depotBody = new LinkedMultiValueMap<>();
                File cniFile = new File("src/main/resources/cni.jpg");
                if (!cniFile.exists()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Fichier CNI introuvable !");
                }
                depotBody.add("piece_cni", new FileSystemResource(cniFile));

                HttpHeaders depotHeaders = new HttpHeaders();
                depotHeaders.setContentType(MediaType.MULTIPART_FORM_DATA);
                HttpEntity<MultiValueMap<String, Object>> depotRequest = new HttpEntity<>(depotBody, depotHeaders);

                ResponseEntity<String> depotResponse = restTemplate.postForEntity(
                        urlBaseTestCharge+"depot/" + idSignataire, depotRequest, String.class);

                if (!depotResponse.getStatusCode().is2xxSuccessful()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Erreur DEPOT : " + depotResponse.getBody());
                }

                stepEnd = System.currentTimeMillis();
                System.out.println("<< Fin DEPOT [" + i + "] - Durée: " + (stepEnd - stepStart) + " ms");

                // -------- SIGNATURE --------
                System.out.println(">> Début SIGNATURE [" + i + "]");
                stepStart = System.currentTimeMillis();

                MultiValueMap<String, Object> signBody = new LinkedMultiValueMap<>();
                File signFile = new File("src/main/resources/SignDoc.pdf");
                if (!signFile.exists()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Fichier PDF à signer introuvable !");
                }

                signBody.add("workerId", "17");
                signBody.add("codePin", codePin);
                signBody.add("filereceivefile", new FileSystemResource(signFile));

                HttpHeaders signHeaders = new HttpHeaders();
                signHeaders.setContentType(MediaType.MULTIPART_FORM_DATA);
                HttpEntity<MultiValueMap<String, Object>> signRequest = new HttpEntity<>(signBody, signHeaders);

                ResponseEntity<String> signResponse = restTemplate.postForEntity(
                        urlBaseTestCharge+"sign_document/" + idSignataire, signRequest, String.class);

                if (!signResponse.getStatusCode().is2xxSuccessful()) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Erreur SIGNATURE : " + signResponse.getBody());
                }

                stepEnd = System.currentTimeMillis();
                System.out.println("<< Fin SIGNATURE [" + i + "] - Durée: " + (stepEnd - stepStart) + " ms");
                System.out.println("<< Temps global 3 operations [" + i + "] - Durée: " + (stepEnd - debutEnrol) + " ms");
            } catch (Exception ex) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erreur inattendue à l'étape [" + i + "] : " + ex.getMessage());
            }
        }

        long endGlobal = System.currentTimeMillis();
        System.out.println("### Simulation terminée en " + (endGlobal - startGlobal) + " ms");

        return ResponseEntity.ok("Simulation complétée en " + (endGlobal - startGlobal) + " ms");
    }
}
