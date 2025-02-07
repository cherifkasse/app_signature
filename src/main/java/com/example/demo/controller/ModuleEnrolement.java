package com.example.demo.controller;

import com.example.demo.model.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class ModuleEnrolement {
    private static final String ALGORITHM = "AES";
    private static final String MODE = "CBC";
    private static final String PADDING = "PKCS5Padding";
    private static final String CIPHER_TRANSFORMATION = ALGORITHM + "/" + MODE + "/" + PADDING;
    private static final byte[] IV = new byte[16];
    private static final Logger logger = LoggerFactory.getLogger(ModuleEnrolement.class);
    Properties prop = null;

    SignerController signerController = new SignerController();
    public ModuleEnrolement() {
        try (InputStream input = ModuleEnrolement.class.getClassLoader().getResourceAsStream("configWin.properties")) {

            prop = new Properties();

            if (input == null) {
                System.out.println("Sorry, unable to find config.properties");
                return;
            }
            //load a properties file from class path, inside static method
            prop.load(input);

        } catch (IOException ex) {
            ex.printStackTrace();

        }
    }
    public ResponseEntity<String> appelerEnroll(SignataireRequest_V2 signataireRequest) {
        String urlAccess = prop.getProperty("url_access");
        RestTemplate restTemplate = new RestTemplate();

        String url = urlAccess + "findSignerByCni/" + signataireRequest.getCni();
        String urlNomSigner = urlAccess + "findSignerBynomSigner/" + signataireRequest.getNomSignataire() + signataireRequest.getIdApplication();
        String urlIdApp = urlAccess + "findSignerByIdApp/" + signataireRequest.getIdApplication();
        String apiUrl = urlAccess + "enroll";
        String renewUrl = urlAccess + "renew";
        String urlInfosCertif = urlAccess + "enregistrerInfosCertif";
        String urlNomWorker = urlAccess + "findNomWorkerById/" + signataireRequest.getIdApplication();

        Worker workerName = restTemplate.getForObject(urlNomWorker, Worker.class);
        Date date_creation = new Date();
        SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String cle_de_signature2 = prop.getProperty("aliasCle") + decouper_nom(signataireRequest.getNomSignataire().trim().toUpperCase()) + signataireRequest.getIdApplication().toString() + "_" + signataireRequest.getCni();

        if (cle_de_signature2.length() > 50) {
            cle_de_signature2 = cle_de_signature2.substring(0, 50);
        }
        String signerKey = cle_de_signature2;

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        try {
            ResponseEntity<Signataire_V2[]> signataireV2 = restTemplate.getForEntity(url, Signataire_V2[].class);
            ResponseEntity<Signataire_V2[]> signataireV2_nom = restTemplate.getForEntity(urlNomSigner, Signataire_V2[].class);
            boolean verifWoker = false;
            if (signataireRequest.getIdApplication() == null || signataireRequest.getNomSignataire() == null
                    || signataireRequest.getCni() == null) {
                String retourMessage = "Veuillez vérifier si toutes les informations sont renseignées";
                logger.info(retourMessage);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(retourMessage);
            }
            if (signataireRequest.getCni().length() < 5) {
                String retourMessage = "La taille du CNI ne peut pas être inférieur à 5.";
                logger.info(retourMessage);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(retourMessage);
            }
            if (signataireRequest.getIdApplication() != null) {
                verifWoker = Boolean.TRUE.equals(restTemplate.getForObject(urlIdApp, Boolean.class));
                if (!verifWoker) {
                    String retourMessage = "ID Application introuvable!";
                    logger.info(retourMessage);
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(retourMessage);
                }
            }

            Signataire_V2[] signatairesArray = signataireV2.getBody();
            Signataire_V2[] signatairesArray_noms = signataireV2_nom.getBody();
            assert signatairesArray != null;
            assert signatairesArray_noms != null;
            List<Signataire_V2> signatairesList = Arrays.asList(signatairesArray);
            List<Signataire_V2> signatairesList_Noms = Arrays.asList(signatairesArray_noms);
            String datePart1 = "";

            if (!signatairesList.isEmpty()) {
//
//                if (!signatairesList_Noms.isEmpty()) {
//                    String conflictMessage = "Person already exists!";
//                    logger.info(conflictMessage);
//                    return ResponseEntity.status(HttpStatus.CONFLICT).body(conflictMessage);
//                }
                //System.out.println("RRRR"+signatairesList.get(0).getNomSignataire());
                //boolean a = signatairesList.get(0).getNomSignataire().equals(signataireRequest.getNomSignataire() + signataireRequest.getIdApplication());
                //System.out.println("RRRR888"+a);
                if (signatairesList.get(0).getNomSignataire().equals(signataireRequest.getNomSignataire() + signataireRequest.getIdApplication())) {
                    datePart1 = signatairesList.get(0).getDateExpiration().split(" ")[0];
                    // Convertir les chaînes de caractères en objets LocalDate
                    LocalDate dateExpiration = LocalDate.parse(datePart1, DateTimeFormatter.ISO_LOCAL_DATE);
                    LocalDate dateAujourdhui = LocalDate.parse(sdf.format(new Date()), DateTimeFormatter.ISO_LOCAL_DATE);
                    if (datePart1.equals(sdf.format(new Date())) || dateAujourdhui.isAfter(dateExpiration)) {
                        ObjectMapper objectMapper = new ObjectMapper();

                        //System.out.println("RRRR888");
                        String conflictMessage = "Renouvellement en cours ";
                        logger.info(conflictMessage);
                        Signataire_V2 signataire_v2 = new Signataire_V2();
                        HttpHeaders headers2 = new HttpHeaders();
                        headers2.setContentType(MediaType.APPLICATION_JSON);
                        signataire_v2.setNomSignataire(signatairesList_Noms.get(0).getNomSignataire());
                        signataire_v2.setCni(signatairesList.get(0).getCni());
                        signataire_v2.setTelephone(signatairesList_Noms.get(0).getTelephone());
                        signataire_v2.setIdApplication(signatairesList_Noms.get(0).getIdApplication());
                        Worker worker = restTemplate.getForObject(urlNomWorker, Worker.class);
                        assert worker != null;
                        // System.out.println("xxxxyyyzzzz" + worker.getNomWorker());
                        signataire_v2.setNomWorker(worker.getNomWorker());
                        InfosCertificat infosCertificat = new InfosCertificat();


                        // Créer une requête HTTP avec l'objet OperationSignature dans le corps
                        HttpEntity<Signataire_V2> requestEntity = new HttpEntity<>(signataire_v2, headers2);
                        // Envoyer la requête HTTP POST
                        ResponseEntity<String> responseEntity = restTemplate.postForEntity(renewUrl, requestEntity, String.class);
                        EnrollResponse_V2 enrollResponse = objectMapper.readValue(responseEntity.getBody(), EnrollResponse_V2.class);
                        ResponseEntity<Signataire_V2[]> signataireV3 = restTemplate.getForEntity(url, Signataire_V2[].class);
                        Signataire_V2[] signatairesArrayV3 = signataireV3.getBody();
                        List<Signataire_V2> signatairesListV3 = Arrays.asList(signatairesArrayV3);
                        enrollResponse.setCodePin(signerController.decryptPin(signatairesListV3.get(0).getCodePin()));
                        enrollResponse.setId_signer(signatairesList.get(0).getIdSigner());
                        String responseBodyWithCodePin = objectMapper.writeValueAsString(enrollResponse);
                        ///Infos certificates


                        infosCertificat.setSignerKey(signerKey);
                        infosCertificat.setNomWorker(workerName.getNomWorker());
                        infosCertificat.setDateCreation(sdf2.format(date_creation));
                        infosCertificat.setDateExpiration(signerController.calculerDateExpirationJours(sdf2.format(date_creation)));
                        HttpEntity<InfosCertificat> requestEntityInfos = new HttpEntity<>(infosCertificat, headers2);
                        ResponseEntity<String> responseEntityInfos = restTemplate.postForEntity(urlInfosCertif, requestEntityInfos, String.class);
                        ///Infos certificats
                        logger.info("Renouvellement avec succès: " + responseBodyWithCodePin);
                        return new ResponseEntity<>(responseBodyWithCodePin, HttpStatus.OK);

                        //return ResponseEntity.status(HttpStatus.OK).body(successMessage);
                    } else {
                        String conflictMessage = "Person already exists!";
                        logger.info(conflictMessage);
                        return ResponseEntity.status(HttpStatus.CONFLICT).body(conflictMessage);
                    }
                }

            }

            // boolean verifWoker = Boolean.FALSE.equals(restTemplate.getForEntity(urlIdApp, Boolean.class));


            if (signataireRequest.getNomSignataire() == null || signataireRequest.getNomSignataire().isEmpty() ||
                    signataireRequest.getCni() == null || signataireRequest.getCni().isEmpty()) {
                String badRequestMessage = "Verifiez si vous avez rempli toutes les informations";
                logger.warn(badRequestMessage);
                return ResponseEntity.badRequest().body(badRequestMessage);
            }

            HttpEntity<SignataireRequest_V2> requestEntity = new HttpEntity<>(signataireRequest, headers);
            if(Objects.equals(signataireRequest.getNomSignataire(), " ")){
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Vérifiez vos informations.");
            }
            ResponseEntity<String> response = restTemplate.postForEntity(apiUrl, requestEntity, String.class);
            logger.info("Requete réussie: " + response.getBody());
            InfosCertificat infosCertificat2 = new InfosCertificat();
            ///Infos certificates
            HttpHeaders headers2 = new HttpHeaders();
            headers2.setContentType(MediaType.APPLICATION_JSON);
            infosCertificat2.setSignerKey(signerKey);
            infosCertificat2.setNomWorker(workerName.getNomWorker());
            infosCertificat2.setDateCreation(sdf2.format(date_creation));
            infosCertificat2.setDateExpiration(signerController.calculerDateExpirationJours(sdf2.format(date_creation)));
            HttpEntity<InfosCertificat> requestEntityInfos2 = new HttpEntity<>(infosCertificat2, headers2);
            ResponseEntity<String> responseEntityInfos2 = restTemplate.postForEntity(urlInfosCertif, requestEntityInfos2, String.class);

            ///Infos certificats
            return response;

        } catch (HttpStatusCodeException e) {
            String errorMessage = "Une erreur est survenue: " + e.getResponseBodyAsString();
            logger.error(errorMessage, e);
            return ResponseEntity.status(e.getStatusCode()).body(errorMessage);
        } catch (Exception e) {
            String generalErrorMessage = "Une erreur inattendue est apparue: " + e.getMessage();
            logger.error(generalErrorMessage, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(generalErrorMessage);
        }
    }

    public String decouper_nom(String nomAChanger) {
        //System.out.println("1er caractere : "+nomAChanger.charAt(0));
        if (nomAChanger.contains(" ")) {
            String[] caract = nomAChanger.split(" ");
            if(caract.length < 1){
                return "Tableau vide!";
            }
            nomAChanger = caract[0] + "_";
            for (int i = 1; i < caract.length; i++) {
                nomAChanger += caract[i].charAt(0);
            }
        }
        if (nomAChanger.length() > 70) {
            nomAChanger = nomAChanger.substring(0, 70);
        }

        return nomAChanger;
    }

}
