package com.example.demo.controller;

import com.example.demo.model.*;
import com.example.demo.utils.QRCodeGenerator;
import com.example.demo.wsdl_client.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.annotations.*;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.http.auth.HttpAuthHeader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import springfox.documentation.annotations.ApiIgnore;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.lang.reflect.Proxy;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;

/**
 * @author Cherif KASSE
 * @project SunuBtrust360_Enrol
 * @created 19/03/2024/03/2024 - 14:48
 */
@RestController
@RequestMapping("/signer/v0.0.2/")
@Api(description = "API de signature")
public class SignerController {
    private static final String ALGORITHM = "AES";
    private static final String MODE = "CBC";
    private static final String PADDING = "PKCS5Padding";
    private static final String CIPHER_TRANSFORMATION = ALGORITHM + "/" + MODE + "/" + PADDING;
    private static final byte[] IV = new byte[16];
    Properties prop = null;
    private static final Logger logger = LoggerFactory.getLogger(SignerController.class);

    @RequestMapping("/")
    @ApiIgnore
    public String hello() {
        return "Gooooooooooodz";
    }

    public SignerController() {
        try (InputStream input = SignerController.class.getClassLoader().getResourceAsStream("configWin.properties")) {

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

    private SecretKey getSecretKey(String keyString) {
        //logger.info("Recuperation clé secrete dans getSecretKey: "+keyString);
        byte[] keyBytes = hexStringToByteArray(keyString);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    private static byte[] hexStringToByteArray(String s) {
        //logger.info("Recuperation clé secrete dans hexStringToByteArray:"+s);
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public String encrypterPin(@PathVariable String pin) {
        try {
            logger.info("########DEBUT PROCESSUS DU CHIFFREMENT DU CODE PIN#########");
            SecretKey secretKey = getSecretKey(prop.getProperty("cleSecrete"));
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
            byte[] encryptedBytes = cipher.doFinal(pin.getBytes(StandardCharsets.UTF_8));
            String encodedPin = Base64.getEncoder().encodeToString(encryptedBytes);
            // Remplacer "/" par "A" et récupérer les indices
            StringBuilder replacedString = new StringBuilder(encodedPin);
            StringBuilder chaineIndex = new StringBuilder(",");
            for (int i = 0; i < replacedString.length(); i++) {
                if (replacedString.charAt(i) == '/') {
                    chaineIndex.append(i);
                    chaineIndex.append(",");
                    replacedString.setCharAt(i, 'A');
                }
            }
            replacedString.append(chaineIndex);
            // Afficher la chaîne après remplacement
            //System.out.println("Chaîne index : " + chaineIndex);
            //System.out.println("Chaîne avant remplacement : " + encodedPin);
            //System.out.println("Chaîne après remplacement : " + replacedString);
            // Afficher les indices des "/"
            logger.info("Code PIN chiffré avec succès !");
            logger.info("########PROCESSUS DU CHIFFREMENT DU CODE PIN TERMINE#########");
            return replacedString.toString();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                 | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            String msg = "Erreur lors du chiffrement.";
            logger.error(msg, e);
            logger.info("########PROCESSUS DU CHIFFREMENT DU CODE PIN TERMINE#########");
            return msg;
        }
    }

    DataResponse rsp = null;

    @PostMapping("sign_document/{id_signer}")
    @ApiOperation(value = "Cette opération permet à l'utilisateur de signer un document. Le document pdf à signer est envoyé sous format de tableau de bytes (binaire).")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Le document a été signé avec succès\n\nParamètres de sortie:\n\n" +
                    "\t{\n\n\t    Document signé sous format tableau de bytes\n\n\t}", examples = @Example(@ExampleProperty(mediaType = "application/pdf", value = "extrait du PDF signé"))),
            @ApiResponse(code = 402, message = "Certificate expired"),
            @ApiResponse(code = 404, message = "ID application introuvable"),
            @ApiResponse(code = 400, message = "La requête est mal formée ou incomplète"),
            @ApiResponse(code = 500, message = "Une erreur interne du serveur s’est produite")
    })
    @ApiImplicitParams({
            @ApiImplicitParam(name = "workerId", value = "ID de l'application appelante fourni par GAINDE 2000.", dataType = "int", paramType = "query", example = "123"),
            // @ApiImplicitParam(name = "filereceivefile", value = "Le document PDF à signer sous format tableau de bytes.", dataType = "file", paramType = "formData",example = "exemple.pdf"),
            @ApiImplicitParam(name = "codePin", value = "Code pour activer les informations du signataire sur le serveur de signature.", dataType = "String", paramType = "query", example = "1234"),
            @ApiImplicitParam(name = "id_signer", value = "Numéro unique d'enrôlement du signataire.", dataType = "int", paramType = "path", example = "456")
    })
    public ResponseEntity<?> Signature_base2(
            @ApiParam(value = "ID de l'application appelante fourni par GAINDE 2000.") @RequestParam(value = "workerId") Integer idWorker,
            @ApiParam(value = "Le document PDF à signer sous format tableau de bytes.") @RequestParam("filereceivefile") MultipartFile file,
            @ApiParam(value = "Code pour activer les informations du signataire sur le serveur de signature.") @RequestParam("codePin") String codePin,
            @ApiParam(value = "Numéro unique d'enrôlement du signataire.") @PathVariable Integer id_signer) throws IOException {
        logger.info("################Debut de traitement de la signature#########################");

        int compteurErreur = 0;
        String datePart1 = "";
        String nomSignataire = "";
        String userkey = "";
        RestTemplate restTemplate = new RestTemplate();
        String urlAccessBdd = prop.getProperty("url_access");
        String url_signer = urlAccessBdd + "findSignerById/" + id_signer;
        String url_signataire = urlAccessBdd + "findSignataireById/" + id_signer;
        String url2 = urlAccessBdd + "ajoutOperation";
        String url3 = urlAccessBdd + "isExistedWorker/" + idWorker;
        String urlNomWorker = urlAccessBdd + "findNomWorkerById/" + idWorker;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        try {
            Signataire_V2 signataireV2 = restTemplate.getForObject(url_signer, Signataire_V2.class);
            Signataire signataire = restTemplate.getForObject(url_signataire, Signataire.class);
            boolean verifWoker = Boolean.TRUE.equals(restTemplate.getForObject(url3, Boolean.class));
            if (idWorker == null) {
                logger.error("Erreur lors de la signature : ID Application introuvable !");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("ID Application introuvable !");
            }
            int workerId = idWorker != null ? idWorker.intValue() : 0;
            if (signataireV2 == null && signataire == null) {
                logger.error("Erreur lors de la signature : Utilisateur inconnu !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Utilisateur inconnu !");
            }

            if (signataireV2 != null) {
                //System.out.println("TESTV2");

                if (!encrypterPin(codePin).equals(signataireV2.getCodePin())) {
                    logger.info("Code pin lors de la signature: " + signataireV2.getCodePin());
                    compteurErreur++;
                } else {
                    compteurErreur = 3;
                    userkey = signataireV2.getSignerKey();
                    logger.info("Code pin lors de la signature: " + signataireV2.getCodePin());
                    logger.info("Clé de signature du signataire: " + userkey);
                    //System.out.println("Code pin lors de la signature: "+signataireV2.getCodePin());
                    datePart1 = signataireV2.getDateExpiration().split(" ")[0];
                    LocalDate dateExpiration = LocalDate.parse(datePart1, DateTimeFormatter.ISO_LOCAL_DATE);
                    LocalDate dateAujourdhui = LocalDate.parse(sdf.format(new Date()), DateTimeFormatter.ISO_LOCAL_DATE);
                    if (datePart1.equals(sdf.format(new Date())) || dateAujourdhui.isAfter(dateExpiration)) {
                        logger.info("Certificate Expired!");
                        //System.out.println("DATEEEE EQUAL :"+sdf.format(new Date()));
                        return ResponseEntity.status(HttpStatus.PAYMENT_REQUIRED).body("Certificate Expired!");

                    }

                    nomSignataire = signataireV2.getNomSignataire();
                }
            }

            if (signataire != null) {
                //System.out.println("TESTV1");

                if (!encrypterPin(codePin).equals(signataire.getCode_pin())) {
                    logger.info("Code pin lors de la signature: " + signataire.getCode_pin());
                    compteurErreur++;
                } else {
                    compteurErreur = 3;
                    userkey = signataire.getSignerKey();
                    logger.info("Code pin lors de la signature: " + signataire.getCode_pin());
                    logger.info("Clé de signature du signataire: " + userkey);
                    datePart1 = signataire.getDate_expiration().split(" ")[0];
                    LocalDate dateExpiration = LocalDate.parse(datePart1, DateTimeFormatter.ISO_LOCAL_DATE);
                    LocalDate dateAujourdhui = LocalDate.parse(sdf.format(new Date()), DateTimeFormatter.ISO_LOCAL_DATE);
                    if (datePart1.equals(sdf.format(new Date())) || dateAujourdhui.isAfter(dateExpiration)) {
                        logger.info("Certificate Expired!");
                        //System.out.println("DATEEEE EQUAL :"+sdf.format(new Date()));
                        return ResponseEntity.status(HttpStatus.PAYMENT_REQUIRED).body("Certificate Expired!");
                    }
                    nomSignataire = signataire.getNomSignataire();
                }
            }
            // System.out.println("DATEEEE EQUAL :"+compteurErreur);
            if (compteurErreur <= 2) {
                logger.error("Erreur lors de la signature : Mauvais Code PIN !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Veuillez fournir un bon code PIN !");
            }

            if (file.isEmpty()) {
                logger.error("Erreur lors de la signature : Fichier introuvable !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Veuillez selectionner un fichier !");
            }
            if (!verifWoker) {
                logger.error("Erreur lors de la signature : ID Application introuvable !");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("ID Application introuvable !");
            }
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);

            //headers.add("X-Keyfactor-Requested-With","");
            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            body.add("filereceivefile", new ByteArrayResource(file.getBytes()) {
                @Override
                public String getFilename() {
                    return file.getOriginalFilename();
                }
            });
            body.add("workerId", workerId);
            //////////////////////////////////////////////////////
            final String serviceURL = prop.getProperty("wsdlUrl_client");
            String keyStoreLocation = prop.getProperty("keystore");
            String trustStoreLocation = prop.getProperty("trustore1");

            String password = prop.getProperty("password_keystore");

            System.setProperty("javax.net.ssl.keyStore", keyStoreLocation);
            System.setProperty("javax.net.ssl.password", password);
            System.setProperty("javax.net.ssl.trustStore", trustStoreLocation);
            System.setProperty("javax.net.ssl.trustStorePassword", password);


            //QName serviceName = new QName("http://www.confiancefactory.com/", "SignServerUser_Cert");
            URL wsdlURL = null;
            try {
                wsdlURL = new URL(serviceURL);
            } catch (MalformedURLException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            ClientWSService service = new ClientWSService(wsdlURL);
            ClientWS port = service.getClientWSPort();
            // System.out.println("#####PORT "+userkey);
            try {
                setupTLS(port, password, userkey.substring(8));
                //  System.out.println("#####PORT "+userkey.substring(8));
            } catch (IOException | GeneralSecurityException e1) {
                // TODO Auto-generated catch block
                //log.error(e1.getMessage());
                e1.printStackTrace();
            }

            try {

                byte[] fileBytes = file.getBytes();
                List<byte[]> bytesFile = new ArrayList<>();
                bytesFile.add(fileBytes);
                System.out.println("clee de sign :" + signataireV2.getSignerKey());
                rsp = port.processData(String.valueOf(workerId), null, fileBytes);
                OperationSignature operationSignature = new OperationSignature();
                HttpHeaders headers2 = new HttpHeaders();
                headers2.setContentType(MediaType.APPLICATION_JSON);
                operationSignature.setIdSigner(id_signer);
                operationSignature.setCodePin(signataireV2.getCodePin());
                operationSignature.setSignerKey(signataireV2.getSignerKey());
                Worker worker = restTemplate.getForObject(urlNomWorker, Worker.class);

                Date dateOp = new Date();

                operationSignature.setDateOperation(sdf.format(dateOp));
                assert worker != null;
                operationSignature.setNomWorker(worker.getNomWorker());

                // Créer une requête HTTP avec l'objet OperationSignature dans le corps
                HttpEntity<OperationSignature> requestEntity = new HttpEntity<>(operationSignature, headers2);
                // Envoyer la requête HTTP POST
                ResponseEntity<OperationSignature> responseEntity = restTemplate.postForEntity(url2, requestEntity, OperationSignature.class);


            } catch (
                    InternalServerException_Exception | RequestFailedException_Exception e) {
                String errorMessage = "Erreur lors de la signature : " + e.getMessage();
                logger.error(errorMessage, e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
            }
            //logger.info("Document signé avec succès");

            return ResponseEntity.ok(rsp.getData());
        } catch (Exception e) {
            String errorMessage = "Une erreur est survenue lors de la signature : " + e.getMessage();
            logger.error(errorMessage, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
        }

    }

    @PostMapping("enroll")
    @ApiOperation(value = "Ce chapitre décrit toutes les opérations exposées par le service de gestion des opérations d’enrôlement d’un signataire. Elle permet à une application d’envoyer les informations nécessaires à l’enrôlement d’un signataire sur le serveur de signature.")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Le signataire a été enrôlé avec succès\n\nParamètres de sortie:\n\n" +
                    "\t{\n\n\t    codePin: Code PIN du signataire\n\n\t    IdSignataire: ID du signataire\n\n\t}"),
            @ApiResponse(code = 400, message = "La requête est mal formée ou incomplète"),
            @ApiResponse(code = 409, message = "Une personne avec ce numéro de CNI existe déjà"),
            @ApiResponse(code = 500, message = "Une erreur interne du serveur s’est produite")
    })
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<String> appelerEnroll(@RequestBody SignataireRequest_V2 signataireRequest) {
        String urlAccess = prop.getProperty("url_access");
        RestTemplate restTemplate = new RestTemplate();

        String url = urlAccess + "findSignerByCni/" + signataireRequest.getCni();
        String urlNomSigner = urlAccess + "findSignerBynomSigner/" + signataireRequest.getNomSignataire() + signataireRequest.getIdApplication();
        String urlIdApp = urlAccess + "findSignerByIdApp/" + signataireRequest.getIdApplication();
        String apiUrl = urlAccess + "enroll";
        String renewUrl = urlAccess + "renew";
        String urlNomWorker = urlAccess + "findNomWorkerById/" + signataireRequest.getIdApplication();

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
                if (signatairesList_Noms.isEmpty()) {
                    String conflictMessage = "Person already exists!";
                    logger.info(conflictMessage);
                    return ResponseEntity.status(HttpStatus.CONFLICT).body(conflictMessage);
                }
                //System.out.println("RRRR"+signatairesList.get(0).getNomSignataire());
                boolean a = signatairesList.get(0).getNomSignataire().equals(signataireRequest.getNomSignataire() + signataireRequest.getIdApplication());
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

                        // Créer une requête HTTP avec l'objet OperationSignature dans le corps
                        HttpEntity<Signataire_V2> requestEntity = new HttpEntity<>(signataire_v2, headers2);
                        // Envoyer la requête HTTP POST
                        ResponseEntity<String> responseEntity = restTemplate.postForEntity(renewUrl, requestEntity, String.class);
                        EnrollResponse_V2 enrollResponse = objectMapper.readValue(responseEntity.getBody(), EnrollResponse_V2.class);
                        ResponseEntity<Signataire_V2[]> signataireV3 = restTemplate.getForEntity(url, Signataire_V2[].class);
                        Signataire_V2[] signatairesArrayV3 = signataireV3.getBody();
                        List<Signataire_V2> signatairesListV3 = Arrays.asList(signatairesArrayV3);
                        enrollResponse.setCodePin(decryptPin(signatairesListV3.get(0).getCodePin()));
                        enrollResponse.setId_signer(signatairesList.get(0).getIdSigner());
                        String responseBodyWithCodePin = objectMapper.writeValueAsString(enrollResponse);
                        logger.info("Enrollment avec succès: " + responseBodyWithCodePin);
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

            ResponseEntity<String> response = restTemplate.postForEntity(apiUrl, requestEntity, String.class);
            logger.info("Requete réussie: " + response.getBody());
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

    public String decryptPin(@PathVariable String pinEncrypted) {
        try {
            logger.info("########DEBUT PROCESSUS DU DECHIFFREMENT DU CODE PIN#########");
            SecretKey secretKey = getSecretKey(prop.getProperty("cleSecrete"));
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));

            List<Integer> indices = new ArrayList<>();
            String[] parts = pinEncrypted.split(",");
            if (parts.length >= 2) {
                StringBuilder chaineRestauree = new StringBuilder(parts[0]);
                for (int i = 1; i < parts.length; i++) {
                    String index = parts[i];
                    indices.add(Integer.parseInt(index));
                }
                for (int index2 : indices) {
                    chaineRestauree.setCharAt(index2, '/');
                }
                //System.out.println(chaineRestauree);
                byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(chaineRestauree.toString()));
                return new String(decryptedBytes, StandardCharsets.UTF_8);
            } else {
                pinEncrypted = parts[0];
                byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(pinEncrypted));
                logger.info("Code PIN déchiffré avec succès !");
                logger.info("########PROCESSUS DU DECHIFFREMENT DU CODE PIN TERMINE#########");
                return new String(decryptedBytes, StandardCharsets.UTF_8);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                 | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            String msg = "Erreur lors du déchiffrement du code PIN";
            logger.error(msg, e);
            logger.info("########PROCESSUS DU DECHIFFREMENT DU CODE PIN TERMINE#########");
            return msg;
        }
    }


    //@ApiIgnore

    //////////////////////////////////////////////////////////////

    private void setupTLS(ClientWS port, String keyPassword, String username)
            throws IOException, GeneralSecurityException {

        // String filename = chemin_keystore.trim()+"ejbca_auth_jks.jks";
        // String filenameTrust = chemin_keystore.trim()+"ejbca_truststore.jks";

        if (port == null) {
            throw new IllegalArgumentException("The port object cannot be null.");
        }

        if (!Proxy.class.isAssignableFrom(port.getClass())) {
            throw new IllegalArgumentException("The given port object is not a proxy instance.");
        }
        // Configuration du conduit HTTP pour utiliser TLS
        HTTPConduit httpConduit = (HTTPConduit) ClientProxy.getClient(port).getConduit();

        //HTTPConduit httpConduit = (HTTPConduit) ((BindingProvider) port).getRequestContext().get(HTTPConduit.class);
        //System.out.println("#####PORT "+httpConduit);
        TLSClientParameters tlsCP = new TLSClientParameters();

        KeyStore keyStore = KeyStore.getInstance("JKS");
        String keyStoreLoc = prop.getProperty("keystore");

        keyStore.load(Files.newInputStream(Paths.get(keyStoreLoc)), keyPassword.toCharArray());
        KeyManager[] myKeyManagers = getKeyManagers(keyStore, keyPassword);
        if (myKeyManagers == null) {
            throw new IllegalArgumentException("The key store cannot be null.");
        }
        tlsCP.setKeyManagers(myKeyManagers);

        KeyStore trustStore = KeyStore.getInstance("JKS");
        String trustStoreLoc = prop.getProperty("trustore1");
        trustStore.load(Files.newInputStream(Paths.get(trustStoreLoc)), keyPassword.toCharArray());
        TrustManager[] myTrustStoreKeyManagers = getTrustManagers(trustStore);
        if (myTrustStoreKeyManagers == null) {
            throw new IllegalArgumentException("The trusted store cannot be null.");
        }

        tlsCP.setTrustManagers(myTrustStoreKeyManagers);

        // The following is not recommended and would not be done in a prodcution
        // environment,
        // this is just for illustrative purpose
        tlsCP.setDisableCNCheck(true);

        httpConduit.setTlsClientParameters(tlsCP);

        // Set client certificate information for authentication (if required)
        AuthorizationPolicy authorizationPolicy = httpConduit.getAuthorization();
        authorizationPolicy.setAuthorizationType(HttpAuthHeader.AUTH_TYPE_BASIC); // Set the appropriate authorization type
        username = username.replaceAll("\\s+", "_");
        authorizationPolicy.setUserName(username);
        authorizationPolicy.setPassword("passe");

    }


    private static TrustManager[] getTrustManagers(KeyStore trustStore)
            throws NoSuchAlgorithmException, KeyStoreException {
        String alg = KeyManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory fac = TrustManagerFactory.getInstance(alg);
        fac.init(trustStore);
        return fac.getTrustManagers();
    }

    private static KeyManager[] getKeyManagers(KeyStore keyStore, String keyPassword)
            throws GeneralSecurityException, IOException {
        String alg = KeyManagerFactory.getDefaultAlgorithm();
        char[] keyPass = keyPassword != null
                ? keyPassword.toCharArray()
                : null;
        KeyManagerFactory fac = KeyManagerFactory.getInstance(alg);
        fac.init(keyStore, keyPass);
        return fac.getKeyManagers();
    }

    ///////////////////////////DEPOT JSUTIFICATIF
    @PostMapping("depot/{idSignataire}")
    @ApiOperation(value = "Cette section permet à l’application métier qui a effectué un enrôlement de téléverser une copie d'un document d'identité pour un signataire existant dans le système. En téléversant une pièce d'identité, les opérateurs du centre d’enregistrement peuvent vérifier et authentifier l'identité du signataire. Cette fonctionnalité améliore les mesures de sécurité et garantit le respect des protocoles de vérification d'identité.")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Le fichier a été téléchargé avec succès", response = String.class),
            @ApiResponse(code = 400, message = "L’ID du signataire n’existe pas ou aucun fichier n’a été fourni"),
            @ApiResponse(code = 500, message = "Une erreur interne du serveur s’est produite")
    })
    @ApiImplicitParams({
            @ApiImplicitParam(name = "idSignataire", value = "L'identifiant du signataire.", dataType = "int", paramType = "query", example = "123"),
            @ApiImplicitParam(name = "piece_cni", value = "Le document justificatif de la pièce d'identité (photo, pdf, ...) sous format tableau de bytes.", dataType = "file", paramType = "query"),
    })
    public ResponseEntity<String> uploadPieceIdentite(@PathVariable Integer idSignataire,
                                                      @RequestParam("piece_cni") @ApiParam(value = "Le document justificatif de la pièce d'identité (photo, pdf, ...) sous format tableau de bytes.") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Fichier non existant !");
        }
        RestTemplate restTemplate = new RestTemplate();
        String urlAccessBdd = prop.getProperty("url_access");
        String url = urlAccessBdd + "depot/" + idSignataire;
        HttpHeaders headers_upload = new HttpHeaders();
        headers_upload.setContentType(MediaType.MULTIPART_FORM_DATA);
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("piece_cni", file.getResource());
        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers_upload);
        ResponseEntity<String> response;
        try {
            response = restTemplate.postForEntity(url, requestEntity, String.class);
        } catch (HttpClientErrorException ex) {
            // Capture les erreurs 4xx (ex: 400 Bad Request)
            return new ResponseEntity<>(ex.getResponseBodyAsString(), ex.getStatusCode());
        } catch (HttpServerErrorException ex) {
            // Capture les erreurs 5xx (ex: 500 Internal Server Error)
            return new ResponseEntity<>(ex.getResponseBodyAsString(), ex.getStatusCode());
        } catch (Exception ex) {
            // Capture d'autres exceptions
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Une erreur s'est produite lors de l'appel de l'API : " + ex.getMessage());
        }
        EnrollResponse_V2 enrollResponseV2 = new EnrollResponse_V2();
        enrollResponseV2.setId_signer(10);
        enrollResponseV2.setCodePin("123456");

        return response;
    }


    //////////////////comrise entre deux dates/////////////////////////////////////////////
    public boolean isDateCompriseEntre(String dateEntre, String dateDebut, String dateFin) {
        final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate entre = LocalDate.parse(dateEntre, DATE_FORMATTER);
        LocalDate debut = LocalDate.parse(dateDebut, DATE_FORMATTER);
        LocalDate fin = LocalDate.parse(dateFin, DATE_FORMATTER);

        return (entre.isEqual(debut) || entre.isAfter(debut)) && (entre.isEqual(fin) || entre.isBefore(fin));
    }

    ////////////////////////////// Liste Cert_Sign////////////////////////////////////////////
    private List<Map<String, Object>> mapToMap(List<Object[]> rawList, String operation) {
        List<Map<String, Object>> mapList = new ArrayList<>();
        String date = null;
        if (Objects.equals(operation, "CERT")) {
            date = "Date Création";
        }
        if (Objects.equals(operation, "SIGN")) {
            date = "Date Signature";
        }
        for (Object[] raw : rawList) {
            Map<String, Object> map = new HashMap<>();
            map.put("Id signataire", ((Number) raw[0]).longValue());
            map.put(date, raw[1].toString());
            map.put("Application appelante", raw[2].toString());
            mapList.add(map);
        }
        return mapList;
    }

    // Fonction split date
    public String[] split_date(String date) {
        return date.split("-");
    }

    @GetMapping("liste_cert_sign/{date1}/{date2}/{nomWorker}/{operation}")
    @ApiOperation(value = "Cette  opération renvoie une liste de signataires ou d'opérations de signature selon le type de l'opération, une plage de date et le nom de l'application appelante.")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Parametre de sortie : la liste de signataire ou d'operation de signature"),
            @ApiResponse(code = 400, message = "Format de date ou type d'opératoin non reconnue"),
            @ApiResponse(code = 500, message = "Une erreur interne du serveur s’est produite")
    })
    public ResponseEntity<?> getListCertSign(
            @ApiParam(value = "La date de début pour la recherche avec le format 'YYYY-MM-JJ'") @PathVariable String date1,
            @ApiParam(value = "La date de fin pour la recherche avec le format 'YYYY-MM-JJ'") @PathVariable String date2,
            @ApiParam(value = "Le nom de l'application appelante") @PathVariable String nomWorker,
            @ApiParam(value = "Le type d'opération: CERT ou SIGN") @PathVariable String operation) {
        try {
            logger.info("Début de demande de liste signataire ou opération");
            RestTemplate restTemplate = new RestTemplate();
            String urlAccessBdd = prop.getProperty("url_access");
            String urlFindSigner = urlAccessBdd + "findSignerBynomWorkerBetweenDate/" + date1 + "/" + date2 + "/" + nomWorker;
            String urlFindOperation = urlAccessBdd + "findOperationBynomWorkerBetweenDate/" + date1 + "/" + date2 + "/" + nomWorker;
            if (verifFormatDate(date1))
                return ResponseEntity.badRequest().body("Vérifier votre format de date 'YYYY-MM-JJ'");
            if (verifFormatDate(date2))
                return ResponseEntity.badRequest().body("Vérifier votre format de date 'YYYY-MM-JJ'");
            if (date1.compareTo(date2) > 0) {
                logger.error("La date de début doit etre inférieur à la date de Fin");
                return ResponseEntity.badRequest().body("La date de début doit être inférieure à la date de Fin");
            }

            if (operation.equals("CERT")) {
                logger.info("Récupération de la liste des signataires");
                ResponseEntity<List<Object[]>> response = restTemplate.exchange(
                        urlFindSigner,
                        HttpMethod.GET,
                        null,
                        new ParameterizedTypeReference<List<Object[]>>() {
                        }
                );
                List<Object[]> rawList = response.getBody();
                List<Map<String, Object>> signataireV2 = mapToMap(rawList, operation);
                return ResponseEntity.ok(signataireV2);
            } else if (operation.equals("SIGN")) {
                logger.info("Récupération de la liste des opérations");
                ResponseEntity<List<Object[]>> response = restTemplate.exchange(
                        urlFindOperation,
                        HttpMethod.GET,
                        null,
                        new ParameterizedTypeReference<List<Object[]>>() {
                        }
                );
                List<Object[]> rawList = response.getBody();
                List<Map<String, Object>> operationList = mapToMap(rawList, operation);
                return ResponseEntity.ok(operationList);
            } else {

                logger.warn("Type d'opération non reconnu");
                return ResponseEntity.badRequest().body("Type d'opération non reconnu");
            }
        } catch (HttpStatusCodeException e) {
            String errorMessage = "Erreur HTTP survenue: " + e.getResponseBodyAsString();
            logger.error(errorMessage, e);
            return ResponseEntity.status(e.getStatusCode()).body(errorMessage);
        } catch (Exception e) {
            String generalErrorMessage = "Une erreur inattendue est apparue: " + e.getMessage();
            logger.error(generalErrorMessage, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(generalErrorMessage);
        }
    }

    private boolean verifFormatDate(@PathVariable String date2) {
        if (split_date(date2).length != 3 || split_date(date2)[0].length() != 4 || Integer.parseInt(split_date(date2)[1]) < 1 || Integer.parseInt(split_date(date2)[1]) > 12
                || Integer.parseInt(split_date(date2)[2]) < 1 || Integer.parseInt(split_date(date2)[2]) > 31) {
            logger.error("Vérifier votre format de date");
            return true;
        }
        return false;
    }

    ///////////////////////////TEST SIGNATURE AVEC CODE QR/////////////////////////////////////////////////
    @PostMapping("sign_document_qr_code/{id_signer}")
    @ApiOperation(value = "Cette opération permet à l'utilisateur de signer un document. Le document pdf à signer est envoyé sous format de tableau de bytes (binaire).")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Le document a été signé avec succès\n\nParamètres de sortie:\n\n" +
                    "\t{\n\n\t    Document signé sous format tableau de bytes\n\n\t}", examples = @Example(@ExampleProperty(mediaType = "application/pdf", value = "extrait du PDF signé"))),
            @ApiResponse(code = 402, message = "Certificate expired"),
            @ApiResponse(code = 404, message = "ID application introuvable"),
            @ApiResponse(code = 400, message = "La requête est mal formée ou incomplète"),
            @ApiResponse(code = 500, message = "Une erreur interne du serveur s’est produite")
    })
    @ApiImplicitParams({
            @ApiImplicitParam(name = "workerId", value = "ID de l'application appelante fourni par GAINDE 2000.", dataType = "int", paramType = "query", example = "123"),
            // @ApiImplicitParam(name = "filereceivefile", value = "Le document PDF à signer sous format tableau de bytes.", dataType = "file", paramType = "formData",example = "exemple.pdf"),
            @ApiImplicitParam(name = "codePin", value = "Code pour activer les informations du signataire sur le serveur de signature.", dataType = "String", paramType = "query", example = "1234"),
            @ApiImplicitParam(name = "id_signer", value = "Numéro unique d'enrôlement du signataire.", dataType = "int", paramType = "path", example = "456"),
            @ApiImplicitParam(name = "X", value = "Coordonnée X pour la position du code QR.", dataType = "int", paramType = "path", example = "100"),
            @ApiImplicitParam(name = "Y", value = "Coordonnée Y pour la position du code QR.", dataType = "int", paramType = "path", example = "100"),
    })
    public ResponseEntity<?> Signature_base_qr_code(
            @ApiParam(value = "ID de l'application appelante fourni par GAINDE 2000.") @RequestParam(value = "workerId") Integer idWorker,
            @ApiParam(value = "Le document PDF à signer sous format tableau de bytes.") @RequestParam("filereceivefile") MultipartFile file,
            @ApiParam(value = "Code pour activer les informations du signataire sur le serveur de signature.") @RequestParam("codePin") String codePin,
            @ApiParam(value = "Coordonnée X pour la position du code QR.") @RequestParam(value = "X", defaultValue = "0") Float posX,
            @ApiParam(value = "Coordonnée Y pour la position du code QR.") @RequestParam(value = "Y", defaultValue = "0") Float posY,
            @ApiParam(value = "Numéro unique d'enrôlement du signataire.") @PathVariable Integer id_signer) throws IOException {
        logger.info("################Debut de traitement de la signature#########################");

        int compteurErreur = 0;
        String datePart1 = "";
        String nomSignataire = "";
        String userkey = "";
        RestTemplate restTemplate = new RestTemplate();
        String urlAccessBdd = prop.getProperty("url_access");
        String urlQrCode =prop.getProperty("url_qrCode") + "enregistrerQrCode";
        String urlLastQrCode =prop.getProperty("url_qrCode") + "getLastQrCode";
        String url_signer = urlAccessBdd + "findSignerById/" + id_signer;
        String url_signataire = urlAccessBdd + "findSignataireById/" + id_signer;
        String url2 = urlAccessBdd + "ajoutOperation";
        String url3 = urlAccessBdd + "isExistedWorker/" + idWorker;
        String urlNomWorker = urlAccessBdd + "findNomWorkerById/" + idWorker;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        try {
            Signataire_V2 signataireV2 = restTemplate.getForObject(url_signer, Signataire_V2.class);
            Signataire signataire = restTemplate.getForObject(url_signataire, Signataire.class);
            boolean verifWoker = Boolean.TRUE.equals(restTemplate.getForObject(url3, Boolean.class));
            if (idWorker == null) {
                logger.error("Erreur lors de la signature : ID Application introuvable !");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("ID Application introuvable !");
            }
            int workerId = idWorker != null ? idWorker.intValue() : 0;
            if (signataireV2 == null && signataire == null) {
                logger.error("Erreur lors de la signature : Utilisateur inconnu !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Utilisateur inconnu !");
            }

            if (signataireV2 != null) {
                //System.out.println("TESTV2");

                if (!encrypterPin(codePin).equals(signataireV2.getCodePin())) {
                    logger.info("Code pin lors de la signature: " + signataireV2.getCodePin());
                    compteurErreur++;
                } else {
                    compteurErreur = 3;
                    userkey = signataireV2.getSignerKey();
                    logger.info("Code pin lors de la signature: " + signataireV2.getCodePin());
                    logger.info("Clé de signature du signataire: " + userkey);
                    //System.out.println("Code pin lors de la signature: "+signataireV2.getCodePin());
                    datePart1 = signataireV2.getDateExpiration().split(" ")[0];
                    LocalDate dateExpiration = LocalDate.parse(datePart1, DateTimeFormatter.ISO_LOCAL_DATE);
                    LocalDate dateAujourdhui = LocalDate.parse(sdf.format(new Date()), DateTimeFormatter.ISO_LOCAL_DATE);
                    if (datePart1.equals(sdf.format(new Date())) || dateAujourdhui.isAfter(dateExpiration)) {
                        logger.info("Certificate Expired!");
                        //System.out.println("DATEEEE EQUAL :"+sdf.format(new Date()));
                        return ResponseEntity.status(HttpStatus.PAYMENT_REQUIRED).body("Certificate Expired!");

                    }

                    nomSignataire = signataireV2.getNomSignataire();
                }
            }

            if (signataire != null) {
                //System.out.println("TESTV1");

                if (!encrypterPin(codePin).equals(signataire.getCode_pin())) {
                    logger.info("Code pin lors de la signature: " + signataire.getCode_pin());
                    compteurErreur++;
                } else {
                    compteurErreur = 3;
                    userkey = signataire.getSignerKey();
                    logger.info("Code pin lors de la signature: " + signataire.getCode_pin());
                    logger.info("Clé de signature du signataire: " + userkey);
                    datePart1 = signataire.getDate_expiration().split(" ")[0];
                    LocalDate dateExpiration = LocalDate.parse(datePart1, DateTimeFormatter.ISO_LOCAL_DATE);
                    LocalDate dateAujourdhui = LocalDate.parse(sdf.format(new Date()), DateTimeFormatter.ISO_LOCAL_DATE);
                    if (datePart1.equals(sdf.format(new Date())) || dateAujourdhui.isAfter(dateExpiration)) {
                        logger.info("Certificate Expired!");
                        //System.out.println("DATEEEE EQUAL :"+sdf.format(new Date()));
                        return ResponseEntity.status(HttpStatus.PAYMENT_REQUIRED).body("Certificate Expired!");
                    }
                    nomSignataire = signataire.getNomSignataire();
                }
            }
            // System.out.println("DATEEEE EQUAL :"+compteurErreur);
            if (compteurErreur <= 2) {
                logger.error("Erreur lors de la signature : Mauvais Code PIN !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Veuillez fournir un bon code PIN !");
            }

            if (file.isEmpty()) {
                logger.error("Erreur lors de la signature : Fichier introuvable !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Veuillez selectionner un fichier !");
            }
            if (!verifWoker) {
                logger.error("Erreur lors de la signature : ID Application introuvable !");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("ID Application introuvable !");
            }
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);

            //headers.add("X-Keyfactor-Requested-With","");
            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            body.add("filereceivefile", new ByteArrayResource(file.getBytes()) {
                @Override
                public String getFilename() {
                    return file.getOriginalFilename();
                }
            });
            body.add("workerId", workerId);
            //////////////////////////////////////////////////////
            final String serviceURL = prop.getProperty("wsdlUrl_client");
            String keyStoreLocation = prop.getProperty("keystore");
            String trustStoreLocation = prop.getProperty("trustore1");

            String password = prop.getProperty("password_keystore");

            System.setProperty("javax.net.ssl.keyStore", keyStoreLocation);
            System.setProperty("javax.net.ssl.password", password);
            System.setProperty("javax.net.ssl.trustStore", trustStoreLocation);
            System.setProperty("javax.net.ssl.trustStorePassword", password);


            //QName serviceName = new QName("http://www.confiancefactory.com/", "SignServerUser_Cert");
            URL wsdlURL = null;
            try {
                wsdlURL = new URL(serviceURL);
            } catch (MalformedURLException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            ClientWSService service = new ClientWSService(wsdlURL);
            ClientWS port = service.getClientWSPort();
            // System.out.println("#####PORT "+userkey);
            try {
                setupTLS(port, password, userkey.substring(8));
                //  System.out.println("#####PORT "+userkey.substring(8));
            } catch (IOException | GeneralSecurityException e1) {
                // TODO Auto-generated catch block
                //log.error(e1.getMessage());
                e1.printStackTrace();
            }

            try {

                byte[] fileBytes = file.getBytes();
                byte[] signedDocumentBytes = null;
                List<byte[]> bytesFile = new ArrayList<>();
                bytesFile.add(fileBytes);
                /////////////////////////////////TEST GENERATION QR CODE /////////////////////////////////////////////
                //Informations pour enregistrer le QrCode
                QrCode lastQrCode = restTemplate.getForObject(urlLastQrCode, QrCode.class);
                QrCode qrCode = new QrCode();
                qrCode.setNomSignataire(nomSignataire);
                assert signataireV2 != null;
                qrCode.setCni(signataireV2.getCni());
                qrCode.setTelephone(signataireV2.getTelephone());
                qrCode.setSignerKey(signataireV2.getSignerKey());
                qrCode.setNomDocument(file.getOriginalFilename());
                qrCode.setDateSignature(sdf.format(new Date()));

                // Génération du QR code et ajout au document PDF
                Rectangle freeZone = null;
                try (PDDocument document = PDDocument.load(new ByteArrayInputStream(fileBytes))) {
                    int numberOfPages = document.getNumberOfPages();
                    // Récupérer l'index de la dernière page
                    PDPage lastPage = document.getPage(numberOfPages - 1);
                    System.out.println(numberOfPages);
                    PDPage page = document.getPage(numberOfPages - 1); // Ajouter le QR code à la première page
                    if (posX == null && posY == null) {
                        // Trouver une zone libre
                        freeZone = QRCodeGenerator.findFreeAreaOnPage(lastPage, 100, 100);
                        if (freeZone == null) {
                            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Aucune zone libre trouvée pour placer le QR code.");
                        }
                    }
                    // Ajouter le QR code
                    try (PDPageContentStream contentStream = new PDPageContentStream(document, page, PDPageContentStream.AppendMode.APPEND, true, true)) {
                        assert lastQrCode != null;
                        byte[] qrCodeImage = QRCodeGenerator.generateQRCodeImage(prop.getProperty("url_infos_qrCode")+(lastQrCode.getId()+1), 100, 100);
                        PDImageXObject pdImage = PDImageXObject.createFromByteArray(document, qrCodeImage, "qrCode");
                        if (posX != null && posY != null) {
                            // Utiliser les coordonnées spécifiées
                            contentStream.drawImage(pdImage, posX, posY, 100, 100);
                        } else {
                            // Utiliser la zone libre trouvée
                            assert freeZone != null;
                            contentStream.drawImage(pdImage, freeZone.x, freeZone.y, 100, 100);
                        }
                        if (freeZone != null) {
                            // Déterminez la position où vous voulez placer le QR code
                            contentStream.drawImage(pdImage, 1, 100, 100, 100);// Ajustez la position et la taille si nécessaire
                        }

                    }

                    // Sauvegarder le document dans un ByteArrayOutputStream
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    document.save(baos);
                    document.close();

                    // Récupérer les bytes du document modifié
                    signedDocumentBytes = baos.toByteArray();

                    // Retourner le document signé avec le QR code en tant que réponse
                    //return ResponseEntity.ok().contentType(MediaType.APPLICATION_PDF).body(signedDocumentBytes);

                } catch (Exception e) {
                    String errorMessage = "Erreur lors de l'ajout du QR code : " + e.getMessage();
                    logger.error(errorMessage, e);
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
                }
                // System.out.println("clee de sign :"+signataireV2.getSignerKey());
                rsp = port.processData(String.valueOf(workerId), null, signedDocumentBytes);
                OperationSignature operationSignature = new OperationSignature();
                HttpHeaders headers2 = new HttpHeaders();
                headers2.setContentType(MediaType.APPLICATION_JSON);
                operationSignature.setIdSigner(id_signer);
                operationSignature.setCodePin(signataireV2.getCodePin());
                operationSignature.setSignerKey(signataireV2.getSignerKey());
                Worker worker = restTemplate.getForObject(urlNomWorker, Worker.class);
                qrCode.setWorkerName(worker.getNomWorker());

                Date dateOp = new Date();

                operationSignature.setDateOperation(sdf.format(dateOp));
                assert worker != null;
                operationSignature.setNomWorker(worker.getNomWorker());

                // Créer une requête HTTP avec l'objet OperationSignature dans le corps
                HttpEntity<OperationSignature> requestEntity = new HttpEntity<>(operationSignature, headers2);
                //Creer la requete avec l'objet QrCode
                HttpEntity<QrCode> requestEntityQrCode = new HttpEntity<>(qrCode, headers2);
                ResponseEntity<QrCode> responseEntityQrCode = restTemplate.postForEntity(urlQrCode, requestEntityQrCode, QrCode.class);
                // Envoyer la requête HTTP POST
                ResponseEntity<OperationSignature> responseEntity = restTemplate.postForEntity(url2, requestEntity, OperationSignature.class);


            } catch (
                    InternalServerException_Exception | RequestFailedException_Exception e) {
                String errorMessage = "Erreur lors de la signature : " + e.getMessage();
                logger.error(errorMessage, e);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
            }
            //logger.info("Document signé avec succès");

            return ResponseEntity.ok(rsp.getData());
        } catch (Exception e) {
            String errorMessage = "Une erreur est survenue lors de la signature : " + e.getMessage();
            logger.error(errorMessage, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
        }

    }

}
