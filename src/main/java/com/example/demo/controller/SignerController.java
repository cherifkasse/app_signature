package com.example.demo.controller;

import com.example.demo.model.*;
import com.example.demo.utils.QRCodeGenerator;
import com.example.demo.utils.Utils;
import com.example.demo.wsdl_client.*;
import com.fasterxml.jackson.core.JsonParser;
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
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.*;
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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.*;
import javax.servlet.http.HttpServletRequest;

/**
 * @author Cherif KASSE
 * @project SunuBtrust360_Enrol
 * @created 19/03/2024/03/2024 - 14:48
 */
@RestController
@RequestMapping("/signer/v1.1/")
@Api(description = "API de signature")
public class SignerController {
    private static final String ALGORITHM = "AES";
    private static final String MODE = "CBC";
    private static final String PADDING = "PKCS5Padding";
    private static final String CIPHER_TRANSFORMATION = ALGORITHM + "/" + MODE + "/" + PADDING;
    private static final byte[] IV = new byte[16];
    private static final Logger logger = LoggerFactory.getLogger(SignerController.class);
    Properties prop = null;
    DataResponse rsp = null;

    String texteRetourControlAccess = "Vous n'êtes pas autorisé à accéder à cette ressource.\n" +
            "Merci de bien vouloir vous limiter aux ressources que vous avez demandées.";

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

    @RequestMapping("/")
    @ApiIgnore
    public String hello() {
        return "Gooooooooooodz";
    }

    private SecretKey getSecretKey(String keyString) {
        //logger.info("Recuperation clé secrete dans getSecretKey: "+keyString);
        byte[] keyBytes = hexStringToByteArray(keyString);
        return new SecretKeySpec(keyBytes, ALGORITHM);
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
            @ApiParam(value = "Numéro unique d'enrôlement du signataire.") @PathVariable Integer id_signer,HttpServletRequest request) throws IOException {
        logger.info("################Debut de traitement de la signature "+id_signer+" #########################");
        int compteurErreur = 0;
        String datePart1 = "";
        String nomSignataire = "";
        String userkey = "";
        RestTemplate restTemplate = new RestTemplate();
        String urlAccessBdd = prop.getProperty("url_access");
        String urlControlCert = urlAccessBdd + "checkUid";
        String url_signer = urlAccessBdd + "findSignerById/" + id_signer;
        String url_signataire = urlAccessBdd + "findSignataireById/" + id_signer;
        String url2 = urlAccessBdd + "ajoutOperation";
        String url3 = urlAccessBdd + "isExistedWorker/" + idWorker;
        String urlNomWorker = urlAccessBdd + "findNomWorkerById/" + idWorker;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

        long startGlobal = System.currentTimeMillis();

        try {
//            X509Certificate[] certs = (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");
//
//            X509Certificate certif_client= certs[0];
//
//            SubjectPublicKeyInfo publicKeyInfo=getSubjectPublicKeyInfo(certif_client);
//            byte[] sbytes = publicKeyInfo.getPublicKeyData().getBytes();
//            String Uniq_ID=getSHA256FingerprintAsString(sbytes);
//            System.out.println("Certificat trouvés :"+Uniq_ID);
//            logger.info("Certificat trouvés :"+Uniq_ID);
//            if(!Uniq_ID.isEmpty()) {
//                return ResponseEntity.status(HttpStatus.OK).body("Certificats trouvés: "+Uniq_ID);
//            }
            long startCheckUid = System.currentTimeMillis();
            RestTemplate restTemplateS = new RestTemplate();
            if (Objects.equals(prop.getProperty("isControlAccess"), "1")) {
                String uid = calculateUidCert(request);
                String nomTable = "sign_document";
                logger.info("UUID CERT :" + uid);
                String url = String.format(urlControlCert + "?tableName=%s&uid=%s", nomTable, uid);
                Boolean exists = restTemplateS.getForObject(url, Boolean.class);
                if (!exists) {
                    logger.error(texteRetourControlAccess);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(texteRetourControlAccess);
                }
            }

            logDuration("Vérification certificat authentification", startCheckUid);

            startCheckUid = System.currentTimeMillis();
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

            logDuration("Vérification Certificat Utilisateurs", startCheckUid);

            startCheckUid = System.currentTimeMillis();

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

            logDuration("Vérification informations Utilisateurs", startCheckUid);

            startCheckUid = System.currentTimeMillis();

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

            logDuration("Récupération du docoment à signer", startCheckUid);

            startCheckUid = System.currentTimeMillis();
            /// Appel fonction creation PDF : Entrée
            String fileName = "";
            if (Objects.equals(prop.getProperty("tracer"), "1")) {
                if (signataireV2 != null) {
                    fileName = id_signer + "_" + signataireV2.getSignerKey();
                    Utils.createPdf(file.getBytes(), id_signer, signataireV2.getSignerKey(), fileName, prop);
                }
                if (signataire != null) {
                    fileName = id_signer + "_" + signataire.getSignerKey();
                    Utils.createPdf(file.getBytes(), id_signer, signataire.getSignerKey(), fileName, prop);
                }

            }
            logDuration("Sauvegarde du document à signer dans tracer", startCheckUid);

            startCheckUid = System.currentTimeMillis();

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

            logDuration("connection via keystore-trustore", startCheckUid);

            startCheckUid = System.currentTimeMillis();

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
               System.out.println("#####PORT " + userkey.substring(8));
            } catch (IOException | GeneralSecurityException e1) {
                // TODO Auto-generated catch block
                //log.error(e1.getMessage());
                e1.printStackTrace();
            }

            byte[] fileBytes = file.getBytes();
            List<byte[]> bytesFile = new ArrayList<>();
            bytesFile.add(fileBytes);
            //System.out.println("clee de sign :" + signataireV2.getSignerKey());
            rsp = port.processData(String.valueOf(workerId), null, fileBytes);
            OperationSignature operationSignature = new OperationSignature();
            HttpHeaders headers2 = new HttpHeaders();
            headers2.setContentType(MediaType.APPLICATION_JSON);
            operationSignature.setIdSigner(id_signer);
            if (signataireV2 != null) {
                operationSignature.setCodePin(signataireV2.getCodePin());
                operationSignature.setSignerKey(signataireV2.getSignerKey());
            } else {
                operationSignature.setCodePin(signataire.getCode_pin());
                operationSignature.setSignerKey(signataire.getSignerKey());
            }

            Worker worker = restTemplate.getForObject(urlNomWorker, Worker.class);

            Date dateOp = new Date();

            operationSignature.setDateOperation(sdf.format(dateOp));
            assert worker != null;
            operationSignature.setNomWorker(worker.getNomWorker());

            // Créer une requête HTTP avec l'objet OperationSignature dans le corps
            HttpEntity<OperationSignature> requestEntity = new HttpEntity<>(operationSignature, headers2);
            // Envoyer la requête HTTP POST
            ResponseEntity<OperationSignature> responseEntity = restTemplate.postForEntity(url2, requestEntity, OperationSignature.class);

            logDuration("Signature document", startCheckUid);

            startCheckUid = System.currentTimeMillis();

            //logger.info("Document signé avec succès");
            /// Appel fonction creation PDF : Sortie
            if (Objects.equals(prop.getProperty("tracer"), "1")) {
                if (signataireV2 != null) {
                    fileName = "sign_" + id_signer + "_" + signataireV2.getSignerKey();
                    Utils.createPdf(rsp.getData(), id_signer, signataireV2.getSignerKey(), fileName, prop);
                }
                if (signataire != null) {
                    fileName = "sign_" + id_signer + "_" + signataire.getSignerKey();
                    Utils.createPdf(rsp.getData(), id_signer, signataire.getSignerKey(), fileName, prop);
                }

            }
            logDuration("Sauvegarde du document signé dans tracer et Fin",startCheckUid);

           //ystem.out.println("RESPONSE : " + Arrays.toString(rsp.getData()));
            logger.info("################ Fin de traitement de la signature "+id_signer+" #########################");
            logDuration("Traitement globale signature", startGlobal);
            return ResponseEntity.ok(rsp.getData());

        } catch (Exception e) {

            String errorMessage = "Une erreur est survenue lors de la signature : " + e.getMessage();
            logger.error(errorMessage, e);
            logDuration("Echec signature et Fin",startGlobal);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
        }



    }


    //@ApiIgnore

    /// ///////////////////////////////////////////////////////////

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
    public ResponseEntity<?> appelerEnroll(@RequestBody SignataireRequest_V2 signataireRequest, HttpServletRequest request) {
        String urlAccess = prop.getProperty("url_access");
        RestTemplate restTemplate = new RestTemplate();
        logger.info("Requête reçue : {}", signataireRequest.toString());

        // Affichage explicite des espaces pour des champs individuels
        logger.info("Détail des champs : nomSignataire='{}', cni='{}', telephone='{}', idApplication='{}'",
                signataireRequest.getNomSignataire(),
                signataireRequest.getCni(),
                signataireRequest.getTelephone(),
                signataireRequest.getIdApplication());

        String url = urlAccess + "findSignerByCni/" + signataireRequest.getCni();
        String urlNomSigner = urlAccess + "findSignerBynomSigner/" + signataireRequest.getNomSignataire() + signataireRequest.getIdApplication();
        String urlIdApp = urlAccess + "findSignerByIdApp/" + signataireRequest.getIdApplication();
        String apiUrl = urlAccess + "enroll";
        String urlControlCert = urlAccess + "checkUid";
        String renewUrl = urlAccess + "renew";
        String urlInfosCertif = urlAccess + "enregistrerInfosCertif";
        String urlNomWorker = urlAccess + "findNomWorkerById/" + signataireRequest.getIdApplication();

        Worker workerName = restTemplate.getForObject(urlNomWorker, Worker.class);
        Date date_creation = new Date();
        SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String messageRetourDecouper = decouper_nom(signataireRequest.getNomSignataire().trim().toUpperCase()) + signataireRequest.getIdApplication().toString();
        if (messageRetourDecouper.equals("Tableau vide!")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Erreur: Informations absentes.");
        }
        String cle_de_signature2 = prop.getProperty("aliasCle") + messageRetourDecouper + "_" + signataireRequest.getCni();

        if (cle_de_signature2.length() > 50) {
            cle_de_signature2 = cle_de_signature2.substring(0, 50);
        }
        InfosCertificat infosCertificat = new InfosCertificat();
        String signerKey = cle_de_signature2;

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        try {
            RestTemplate restTemplateS = new RestTemplate();
            if (Objects.equals(prop.getProperty("isControlAccess"), "1")){
                String uid = calculateUidCert(request);
                String nomTable = "enroll";
                logger.info("UUID CERT :"+uid);
                String urlControl = String.format(urlControlCert+"?tableName=%s&uid=%s",nomTable, uid);
                Boolean exists = restTemplateS.getForObject(urlControl, Boolean.class);
                if(!exists) {
                    logger.error(texteRetourControlAccess);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(texteRetourControlAccess);
                }
            }

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
            String certifUser ="";

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

                        // Créer une requête HTTP avec l'objet OperationSignature dans le corps
                        HttpEntity<Signataire_V2> requestEntity = new HttpEntity<>(signataire_v2, headers2);
                        // Envoyer la requête HTTP POST
                        ResponseEntity<String> responseEntity = restTemplate.postForEntity(renewUrl, requestEntity, String.class);
                        EnrollResponse_V2 enrollResponse = objectMapper.readValue(responseEntity.getBody(), EnrollResponse_V2.class);
                        certifUser = enrollResponse.getCertificate();
                        ResponseEntity<Signataire_V2[]> signataireV3 = restTemplate.getForEntity(url, Signataire_V2[].class);
                        Signataire_V2[] signatairesArrayV3 = signataireV3.getBody();
                        List<Signataire_V2> signatairesListV3 = Arrays.asList(signatairesArrayV3);
                        enrollResponse.setCodePin(decryptPin(signatairesListV3.get(0).getCodePin()));
                        enrollResponse.setId_signer(signatairesList.get(0).getIdSigner());
                        String responseBodyWithCodePin = objectMapper.writeValueAsString(enrollResponse);
                        ///Infos certificates


                        infosCertificat.setSignerKey(signerKey);
                        infosCertificat.setNomWorker(workerName.getNomWorker());
                        infosCertificat.setDateCreation(sdf2.format(date_creation));
                        String siExpiration7Jours = prop.getProperty("expiration_certificat");
                        if (siExpiration7Jours ==  "1"){
                            infosCertificat.setDateExpiration(calculerDateExpirationJours(sdf2.format(date_creation)));
                        }
                        else{
                            X509Certificate certif = convertStringToX509(enrollResponse.getCertificate());
                            // System.out.println("Total expiration :"+certif.getNotAfter());
                            infosCertificat.setDateExpiration(sdf2.format(certif.getNotAfter()));
                        }
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
            if (Objects.equals(signataireRequest.getNomSignataire(), " ")) {
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
            ObjectMapper objectMapper = new ObjectMapper();
            EnrollResponse_V2 enrollResponse = objectMapper.readValue(response.getBody(), EnrollResponse_V2.class);
            String siExpiration7Jours = prop.getProperty("expiration_certificat");
            if (siExpiration7Jours ==  "1"){
                infosCertificat2.setDateExpiration(calculerDateExpirationJours(sdf2.format(date_creation)));
            }
            else{
                X509Certificate certif = convertStringToX509(enrollResponse.getCertificate());
               // System.out.println("Total expiration :"+certif.getNotAfter());
                infosCertificat2.setDateExpiration(sdf2.format(certif.getNotAfter()));
            }

            HttpEntity<InfosCertificat> requestEntityInfos2 = new HttpEntity<>(infosCertificat2, headers2);
            ResponseEntity<String> responseEntityInfos2 = restTemplate.postForEntity(urlInfosCertif, requestEntityInfos2, String.class);

            ///Infos certificats
            return response;

        } catch (HttpStatusCodeException e) {
            if (e.getStatusCode() == HttpStatus.BAD_REQUEST) {
                String errorMessage = e.getResponseBodyAsString();
                logger.error(errorMessage, e);
                return ResponseEntity.badRequest().body(errorMessage);
            }
            String errorMessage =  e.getResponseBodyAsString();
            logger.error(errorMessage, e);
            return ResponseEntity.status(e.getStatusCode()).body(errorMessage);
        } catch (Exception e) {
            String generalErrorMessage = e.getMessage();
            logger.error(generalErrorMessage, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(generalErrorMessage);
        }

    }

    @PostMapping("decrypt/{pinEncrypted}")

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


    private void setupTLS_sans_nom(ClientWS port, String keyPassword)
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

    }

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

    /// ////////////////////////DEPOT JSUTIFICATIF
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


    /// ///////////////comrise entre deux dates/////////////////////////////////////////////
    public boolean isDateCompriseEntre(String dateEntre, String dateDebut, String dateFin) {
        final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate entre = LocalDate.parse(dateEntre, DATE_FORMATTER);
        LocalDate debut = LocalDate.parse(dateDebut, DATE_FORMATTER);
        LocalDate fin = LocalDate.parse(dateFin, DATE_FORMATTER);

        return (entre.isEqual(debut) || entre.isAfter(debut)) && (entre.isEqual(fin) || entre.isBefore(fin));
    }

    /// /////////////////////////// Liste Cert_Sign////////////////////////////////////////////
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

    @GetMapping("getAllOperations")
    public ResponseEntity<?> getAllOperations() {
        String url_access = prop.getProperty("url_access");
        String urlGetOperations = url_access + "getAllOperations";
        try {
            logger.info("Récupération de la liste des opérations");
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<List<OperationSignature>> responseEntity = restTemplate.exchange(
                    urlGetOperations,
                    HttpMethod.GET,
                    null,
                    new ParameterizedTypeReference<List<OperationSignature>>() {
                    }
            );

            List<OperationSignature> listeOp = responseEntity.getBody();
            return ResponseEntity.ok(listeOp);

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

    /// ////////////////////////TEST SIGNATURE AVEC CODE QR/////////////////////////////////////////////////
    @PostMapping("sign_document_qr_code/{id_signer}")
    @ApiOperation(value = "Cette opération permet à l'utilisateur de signer un document et d'apposer un Code QR qur le document. Le document pdf à signer est envoyé sous format de tableau de bytes (binaire).")
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
            @ApiImplicitParam(name = "X", value = "Optionnel\nPartie X des coordonnées (x,y) pour la position de départ du code QR.", dataType = "int", paramType = "query", example = "100"),
            @ApiImplicitParam(name = "Y", value = "Optionnel\nPartie Y des coordonnées (x,y) pour la position de départ du code QR.", dataType = "int", paramType = "query", example = "100"),
    })
    public ResponseEntity<?> Signature_base_qr_code(
            @ApiParam(value = "ID de l'application appelante fourni par GAINDE 2000.") @RequestParam(value = "workerId", required = false) Integer idWorker,
            @ApiParam(value = "Le document PDF à signer sous format tableau de bytes.") @RequestParam("filereceivefile") MultipartFile file,
            @ApiParam(value = "Code pour activer les informations du signataire sur le serveur de signature.") @RequestParam("codePin") String codePin,
            @ApiParam(value = "Partie X des coordonnées (x,y) pour la position de départ du code QR.") @RequestParam(value = "X", defaultValue = "0") Float posX,
            @ApiParam(value = "Partie Y des coordonnées (x,y) pour la position de départ du code QR.") @RequestParam(value = "Y", defaultValue = "0") Float posY,
            @ApiParam(value = "Numéro unique d'enrôlement du signataire.") @PathVariable Integer id_signer, HttpServletRequest request) throws IOException {
        logger.info("################Debut de traitement de la signature#########################");
        if (idWorker == null) {
            logger.error("Erreur lors de la signature : ID Application introuvable !");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("ID Application introuvable !");
        }
        int compteurErreur = 0;
        String datePart1 = "";
        String nomSignataire = "";
        String userkey = "";
        RestTemplate restTemplate = new RestTemplate();
        String urlAccessBdd = prop.getProperty("url_access");
        String urlControlCert = urlAccessBdd + "checkUid";
        String urlQrCode = prop.getProperty("url_qrCode") + "enregistrerQrCode";
        String urlLastQrCode = prop.getProperty("url_qrCode") + "getLastQrCode";
        String url_signer = urlAccessBdd + "findSignerById/" + id_signer;
        String url_signataire = urlAccessBdd + "findSignataireById/" + id_signer;
        String url2 = urlAccessBdd + "ajoutOperation";
        String url3 = urlAccessBdd + "isExistedWorker/" + idWorker;
        String urlNomWorker = urlAccessBdd + "findNomWorkerById/" + idWorker;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        DateTimeFormatter sdf2 = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        try {

            RestTemplate restTemplateS = new RestTemplate();
            if (Objects.equals(prop.getProperty("isControlAccess"), "1")){
                String uid = calculateUidCert(request);
                String nomTable = "sign_document_qr_code";
                logger.info("UUID CERT :"+uid);
                String url = String.format(urlControlCert+"?tableName=%s&uid=%s",nomTable, uid);
                Boolean exists = restTemplateS.getForObject(url, Boolean.class);
                if(!exists) {
                    logger.error(texteRetourControlAccess);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(texteRetourControlAccess);
                }
            }

            Signataire_V2 signataireV2 = restTemplate.getForObject(url_signer, Signataire_V2.class);
            Signataire signataire = restTemplate.getForObject(url_signataire, Signataire.class);
            boolean verifWoker = Boolean.TRUE.equals(restTemplate.getForObject(url3, Boolean.class));

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
                if (signataireV2 != null) {
                    qrCode.setCni(signataireV2.getCni());
                    qrCode.setTelephone(signataireV2.getTelephone());
                    qrCode.setSignerKey(signataireV2.getSignerKey());
                } else {
                    qrCode.setCni(signataire.getCniPassport());
                    qrCode.setTelephone("Pas de numéro");
                    qrCode.setSignerKey(signataire.getSignerKey());
                }
                qrCode.setNomDocument(file.getOriginalFilename());
                LocalDateTime now = LocalDateTime.now();
                String formattedDate = now.format(sdf2);
                qrCode.setDateSignature(formattedDate);

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
                        int idLastQrCode = 0;
                        if (lastQrCode != null) {
                            idLastQrCode = Math.toIntExact(lastQrCode.getId());
                        }
                        byte[] qrCodeImage = QRCodeGenerator.generateQRCodeImage(prop.getProperty("url_infos_qrCode") + (idLastQrCode + 1), 100, 100);
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
                if (signataireV2 != null) {
                    operationSignature.setCodePin(signataireV2.getCodePin());
                    operationSignature.setSignerKey(signataireV2.getSignerKey());
                } else {
                    operationSignature.setCodePin(signataire.getCode_pin());
                    operationSignature.setSignerKey(signataire.getSignerKey());
                }


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


    /// ////////////////////////SIGNATURE IMAGE A LA PLACE CODE QR/////////////////////////////////////////////////
    @PostMapping("sign_document_image/{id_signer}")
    @ApiOperation(value = "Cette opération permet à l'utilisateur de signer un document et insérer une image sur le document. Le document pdf à signer est envoyé sous format de tableau de bytes (binaire).")
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
            @ApiImplicitParam(name = "X", value = "Optionnel\nCoordonnée X pour la position du code QR.", dataType = "int", paramType = "path", example = "100"),
            @ApiImplicitParam(name = "Y", value = "Optionnel\nCoordonnée Y pour la position du code QR.", dataType = "int", paramType = "path", example = "100"),
    })
    public ResponseEntity<?> Signature_base_image(
            @ApiParam(value = "ID de l'application appelante fourni par GAINDE 2000.") @RequestParam(value = "workerId") Integer idWorker,
            @ApiParam(value = "Le document PDF à signer sous format tableau de bytes.") @RequestParam("filereceivefile") MultipartFile file,
            @ApiParam(value = "Code pour activer les informations du signataire sur le serveur de signature.") @RequestParam("codePin") String codePin,
            @ApiParam(value = "Optionnel\nCoordonnée X pour la position du code QR.") @RequestParam(value = "X", defaultValue = "0") Float posX,
            @ApiParam(value = "Optionnel\nCoordonnée Y pour la position du code QR.") @RequestParam(value = "Y", defaultValue = "0") Float posY,
            @ApiParam(value = "Image à insérer à la place du QR code.") @RequestParam("image") MultipartFile image,
            @ApiParam(value = "Numéro unique d'enrôlement du signataire.") @PathVariable Integer id_signer,HttpServletRequest request) throws IOException {
        logger.info("################Debut de traitement de la signature#########################");

        int compteurErreur = 0;
        String datePart1 = "";
        String nomSignataire = "";
        String userkey = "";
        RestTemplate restTemplate = new RestTemplate();
        String urlAccessBdd = prop.getProperty("url_access");
        String urlControlCert = urlAccessBdd + "checkUid";
        String urlQrCode = prop.getProperty("url_qrCode") + "enregistrerQrCode";
        String urlLastQrCode = prop.getProperty("url_qrCode") + "getLastQrCode";
        String url_signer = urlAccessBdd + "findSignerById/" + id_signer;
        String url_signataire = urlAccessBdd + "findSignataireById/" + id_signer;
        String url2 = urlAccessBdd + "ajoutOperation";

        String url3 = urlAccessBdd + "isExistedWorker/" + idWorker;
        String urlNomWorker = urlAccessBdd + "findNomWorkerById/" + idWorker;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        try {
            RestTemplate restTemplateS = new RestTemplate();
            if (Objects.equals(prop.getProperty("isControlAccess"), "1")){
                String uid = calculateUidCert(request);
                String nomTable = "sign_document_image";
                logger.info("UUID CERT :"+uid);
                String url = String.format(urlControlCert+"?tableName=%s&uid=%s",nomTable, uid);
                Boolean exists = restTemplateS.getForObject(url, Boolean.class);
                if(!exists) {
                    logger.error(texteRetourControlAccess);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(texteRetourControlAccess);
                }
            }


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
            // Vérifiez si l'image est fournie et non vide
            if (image == null || image.isEmpty()) {
                logger.error("Erreur lors de la signature : Image introuvable !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Veuillez fournir une image à insérer !");
            }
            // Vérification du format de l'image
            String contentType = image.getContentType();
            if (!(contentType.equals("image/png") || contentType.equals("image/jpeg"))) {
                String errorMessage = "Le format de l'image doit être PNG ou JPEG.";
                logger.error(errorMessage);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
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

                // Génération du QR code et ajout au document PDF
                Rectangle freeZone = null;
                try (PDDocument document = PDDocument.load(new ByteArrayInputStream(fileBytes))) {
                    int numberOfPages = document.getNumberOfPages();
                    // Récupérer l'index de la dernière page
                    PDPage lastPage = document.getPage(numberOfPages - 1);
                    //System.out.println(numberOfPages);
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

                        // Convertissez l'image en byte array
                        byte[] imageBytes = image.getBytes();
                        PDImageXObject pdImage = PDImageXObject.createFromByteArray(document, imageBytes, "image");
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
                    String errorMessage = "Erreur lors de l'ajout de l'image sur le document : " + e.getMessage();
                    logger.error(errorMessage, e);
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
                }
                // System.out.println("clee de sign :"+signataireV2.getSignerKey());
                rsp = port.processData(String.valueOf(workerId), null, signedDocumentBytes);
                OperationSignature operationSignature = new OperationSignature();
                HttpHeaders headers2 = new HttpHeaders();
                headers2.setContentType(MediaType.APPLICATION_JSON);
                operationSignature.setIdSigner(id_signer);
                if (signataireV2 != null) {
                    operationSignature.setCodePin(signataireV2.getCodePin());
                    operationSignature.setSignerKey(signataireV2.getSignerKey());
                } else {
                    operationSignature.setCodePin(signataire.getCode_pin());
                    operationSignature.setSignerKey(signataire.getSignerKey());
                }

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


    @PostMapping("sign_document_by_workerID")
    @ApiOperation(value = "Cette opération permet à l'utilisateur de signer un document. Le document pdf à signer est envoyé sous format de tableau de bytes (binaire).")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Le document a été signé avec succès\n\nParamètres de sortie:\n\n" +
                    "\t{\n\n\t    Document signé sous format tableau de bytes\n\n\t}", examples = @Example(@ExampleProperty(mediaType = "application/pdf", value = "extrait du PDF signé"))),
            @ApiResponse(code = 402, message = "Certificate expired"),
            @ApiResponse(code = 404, message = "ID application introuvable"),
            @ApiResponse(code = 400, message = "La requête est mal formée ou incomplète"),
            @ApiResponse(code = 500, message = "Une erreur interne du serveur s’est produite")
    })
//    @ApiImplicitParams({
//            @ApiImplicitParam(name = "workerId", value = "ID de l'application appelante fourni par GAINDE 2000.", dataType = "int", paramType = "query", example = "10"),
//            @ApiImplicitParam(name = "filereceivefile", value = "Le document PDF à signer sous format tableau de bytes.", dataType = "file", paramType = "formData",example = "exemple.pdf")
//
//    })
    public ResponseEntity<?> Signature_base_workerID(
            @ApiParam(value = "ID de l'application appelante fourni par GAINDE 2000.") @RequestParam(value = "workerId", required = false) Integer idWorker,
            @ApiParam(value = "Code Pin pour la startup fourni par GAINDE 2000.") @RequestParam(value = "codePin", required = false) String codePin,
            @ApiParam(value = "Le document PDF à signer sous format tableau de bytes.") @RequestParam("filereceivefile") MultipartFile file, HttpServletRequest request
    ) throws IOException {
        logger.info("################Debut de traitement de la signature#########################");

        if (idWorker == null) {
            logger.error("Erreur lors de la signature : Veuillez renseigner l'id de l'application appelante !");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Veuillez renseigner l'id de l'application appelante!");
        }
        if (codePin == null || codePin.trim().isEmpty()) {
            logger.error("Erreur lors de la signature : Veuillez renseigner votre code pin !");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Veuillez renseigner votre code pin!");
        }
        int compteurErreur = 0;
        String datePart1 = "";
        String nomSignataire = "";
        String userkey = "userkey_default_key";

        RestTemplate restTemplate = new RestTemplate();
        String urlAccessBdd = prop.getProperty("url_access_startup");
        String url2 = urlAccessBdd + "ajoutOperation";
        String urlControlCert = urlAccessBdd + "checkUid";
        String url3 = urlAccessBdd + "isExistedWorker/" + idWorker;
        String url_startup = urlAccessBdd + "findSignerStartup/" + idWorker;
        String urlNomWorker = urlAccessBdd + "findNomWorkerById/" + idWorker;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        try {
            RestTemplate restTemplateS = new RestTemplate();
            if (Objects.equals(prop.getProperty("isControlAccess"), "1")){
                String uid = calculateUidCert(request);
                String nomTable = "sign_document_by_workerID";
                logger.info("UUID CERT :"+uid);
                String url = String.format(urlControlCert+"?tableName=%s&uid=%s",nomTable, uid);
                Boolean exists = restTemplateS.getForObject(url, Boolean.class);
                if(!exists) {
                    logger.error(texteRetourControlAccess);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(texteRetourControlAccess);
                }
            }


            boolean verifWoker = Boolean.TRUE.equals(restTemplate.getForObject(url3, Boolean.class));
            int workerId = idWorker != null ? idWorker.intValue() : 0;

            if (!verifWoker) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("ID application introuvable !");
            }

            SignerStartup signerStartup = restTemplate.getForObject(url_startup, SignerStartup.class);

            assert signerStartup != null;
//            System.out.println("Signer Startup :"+signerStartup.getCodePin());
            if (!signerStartup.getCodePin().equals(encrypterPin(codePin))) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Mauvais code pin !");
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
                setupTLS_sans_nom(port, password);
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
                rsp = port.processData(String.valueOf(workerId), null, fileBytes);
                OperationSignature operationSignature = new OperationSignature();
                HttpHeaders headers2 = new HttpHeaders();
                headers2.setContentType(MediaType.APPLICATION_JSON);
                operationSignature.setIdSigner(idWorker);
                operationSignature.setCodePin("123456");
                operationSignature.setSignerKey("userkey_default_value");
                Worker worker = restTemplate.getForObject(urlNomWorker, Worker.class);
                System.out.println("WORKERRRRR " + worker.getNomWorker());

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


    //Signature avec Image liée à la signature

    @PostMapping("sign_document_image_link_signature/{id_signer}")
    @ApiOperation(value = "Cette opération permet à l'utilisateur de signer un document, de mettre un Code QR qui permet de rediriger vers une page web pour afficher les informations du signataire te de la signature.\n Le document pdf à signer est envoyé sous format de tableau de bytes (binaire).")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Le document a été signé avec succès\n\nParamètres de sortie:\n\n" +
                    "\t{\n\n\t    Document signé sous format tableau de bytes\n\n\t}", examples = @Example(@ExampleProperty(mediaType = "application/pdf", value = "extrait du PDF signé"))),
            @ApiResponse(code = 402, message = "Certificate expired"),
            @ApiResponse(code = 404, message = "ID application introuvable"),
            @ApiResponse(code = 400, message = "La requête est mal formée ou incomplète"),
            @ApiResponse(code = 500, message = "Une erreur interne du serveur s’est produite")
    })

   public ResponseEntity<?> sign_document_image_link_signature(
            @ApiParam(value = "ID de l'application appelante fourni par GAINDE 2000.") @RequestParam(value = "workerId", required = false) Integer idWorker,
            @ApiParam(value = "Le document PDF à signer sous format tableau de bytes.") @RequestParam("filereceivefile") MultipartFile file,
            @ApiParam(value = "Code pour activer les informations du signataire sur le serveur de signature.") @RequestParam("codePin") String codePin,
            @ApiParam(value = "Image à insérer à la place du QR code.") @RequestParam(value = "image") MultipartFile image,
            @ApiParam(value = "Numéro unique d'enrôlement du signataire.") @PathVariable Integer id_signer,
            @ApiParam(value = "Optionnel\nCoordonnée X pour la position du code QR.") @RequestParam(value = "X", defaultValue = "0") Float posX,
            @ApiParam(value = "Optionnel\nCoordonnée Y pour la position du code QR.") @RequestParam(value = "Y", defaultValue = "0") Float posY,
            @ApiParam(value = "Numéro de page sur laquelle apposer l'image.") @RequestParam(value = "numeroPage", defaultValue = "Last") String numeroPage, HttpServletRequest request) throws IOException {
        logger.info("################Debut de traitement de la signature#########################");


        try {
            if (idWorker == null) {
                logger.error("Erreur lors de la signature : ID Application introuvable !");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("ID Application introuvable !");
            }
            if (id_signer == null || id_signer <= 0) {
                logger.error("Erreur lors de la signature : Utilisateur inconnu !");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Utilisateur inconnu !");
            }
            int compteurErreur = 0;
            String datePart1 = "";
            String nomSignataire = "";
            String userkey = "";
            RestTemplate restTemplate = new RestTemplate();
            String base64Image = Base64.getEncoder().encodeToString(image.getBytes());
            String urlAccessBdd = prop.getProperty("url_access");
            String urlControlCert = urlAccessBdd + "checkUid";
            String urlSetWorkerAttr = prop.getProperty("url_access") + "setWorkerAttributes/" + idWorker;
            String url_signer = urlAccessBdd + "findSignerById/" + id_signer;
            String url_signataire = urlAccessBdd + "findSignataireById/" + id_signer;
            String url2 = urlAccessBdd + "ajoutOperation";
            String url3 = urlAccessBdd + "isExistedWorker/" + idWorker;
            String urlNomWorker = urlAccessBdd + "findNomWorkerById/" + idWorker;
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

            Signataire_V2 signataireV2 = restTemplate.getForObject(url_signer, Signataire_V2.class);
            Signataire signataire = restTemplate.getForObject(url_signataire, Signataire.class);
            boolean verifWoker = Boolean.TRUE.equals(restTemplate.getForObject(url3, Boolean.class));

            RestTemplate restTemplateS = new RestTemplate();
            if (Objects.equals(prop.getProperty("isControlAccess"), "1")){
                String uid = calculateUidCert(request);
                String nomTable = "sign_document_image_link_signature";
                logger.info("UUID CERT :"+uid);
                String url = String.format(urlControlCert+"?tableName=%s&uid=%s",nomTable, uid);
                Boolean exists = restTemplateS.getForObject(url, Boolean.class);
                if(!exists) {
                    logger.error(texteRetourControlAccess);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(texteRetourControlAccess);
                }
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
            // Vérifiez si l'image est fournie et non vide
            if (image == null || image.isEmpty()) {
                logger.error("Erreur lors de la signature : Image introuvable !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Veuillez fournir une image à insérer !");
            }
            // Vérification du format de l'image
            String contentType = image.getContentType();
            if (!(contentType.equals("image/png") || contentType.equals("image/jpeg"))) {
                String errorMessage = "Le format de l'image doit être PNG ou JPEG.";
                logger.error(errorMessage);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorMessage);
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


                try (PDDocument document = PDDocument.load(file.getBytes())) {

                    // Détermine la page sur laquelle placer l'image
                    PDPage page;
                    if (numeroPage == null || numeroPage.toString().equalsIgnoreCase("Last")) {
                        page = document.getPage(document.getNumberOfPages() - 1);
                    } else {
                        int pageIndex = Integer.parseInt(numeroPage) - 1; // Les index de page commencent à 0
                        if (pageIndex < 0 || pageIndex >= document.getNumberOfPages()) {
                            logger.error("Numéro de page invalide !");
                            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Numéro de page invalide !");
                        }
                        page = document.getPage(pageIndex);
                    }

                    BufferedImage image_file = ImageIO.read(image.getInputStream());

// Récupérer la largeur et la hauteur de l'image
                    int width = image_file.getWidth();
                    int height = image_file.getHeight();

// Vérification si les coordonnées sont fournies
                    String x1, y1, x2, y2;
                    if (posX != 0 && posY != 0) {
                        // Utilisation des coordonnées fournies
                        x1 = String.valueOf(posX.intValue());
                        y1 = String.valueOf(posY.intValue());
                        x2 = String.valueOf((width));
                        y2 = String.valueOf((height));
                    } else {
                        // Recherche d'une zone libre sur la page
                        PDRectangle freeZone = QRCodeGenerator.findFreeArea(page, 75, 75);
                        if (freeZone == null) {
                            logger.error("Aucune zone libre trouvée pour placer l'image.");
                            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Aucune zone libre trouvée pour placer l'image.");
                        }

                        // Utilisation des coordonnées de la zone libre trouvée
                        x1 = String.valueOf((int) freeZone.getLowerLeftX());
                        y1 = String.valueOf((int) freeZone.getLowerLeftY());
                        x2 = String.valueOf((int) freeZone.getUpperRightX());
                        y2 = String.valueOf((int) freeZone.getUpperRightY());
                    }

// Charger l'image en tant qu'objet PDImageXObject
                    PDImageXObject pdImage = PDImageXObject.createFromByteArray(document, image.getBytes(), "image");

// Ajouter l'image à la page du document
                   // PDPageContentStream contentStream = new PDPageContentStream(document, page);
                    PDPageContentStream contentStream = new PDPageContentStream(document, page, PDPageContentStream.AppendMode.APPEND, true, true);

                    contentStream.drawImage(pdImage, Float.parseFloat(x1), Float.parseFloat(y1), Float.parseFloat(x2) - Float.parseFloat(x1), Float.parseFloat(y2) - Float.parseFloat(y1));
                    contentStream.close();

// Appel à l'API pour définir les coordonnées
                    String urlSetWorkerAttrCoord = prop.getProperty("url_access") + "setWorkerAttributesCoord/" + idWorker + "/" + x1 + "/" + y1 + "/" + x2 + "/" + y2;
                    HttpHeaders headersCoord = new HttpHeaders();
                    headersCoord.setContentType(MediaType.APPLICATION_JSON);
                    HttpEntity<Void> requestEntity = new HttpEntity<>(headersCoord);

                    restTemplate.exchange(
                            urlSetWorkerAttrCoord,
                            HttpMethod.POST,
                            requestEntity,
                            Void.class
                    );

// Sauvegarde du document signé
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    document.save(baos);
                    signedDocumentBytes = baos.toByteArray();


                    // Sauvegarde du document signé via l'API
                    HttpHeaders headersImage = new HttpHeaders();
                    headersImage.setContentType(MediaType.MULTIPART_FORM_DATA);
                    MultiValueMap<String, Object> bodyImage = new LinkedMultiValueMap<>();
                    bodyImage.add("file", new ByteArrayResource(signedDocumentBytes) {
                        @Override
                        public String getFilename() {
                            return file.getOriginalFilename();
                        }
                    });
                    HttpEntity<MultiValueMap<String, Object>> requestImage = new HttpEntity<>(bodyImage, headersImage);


                }
                // Pas de corps pour cette requête POST, uniquement des en-têtes si nécessaire
                HttpHeaders headersWorker = new HttpHeaders();
// Ajoutez des en-têtes si nécessaire
                headersWorker.setContentType(MediaType.MULTIPART_FORM_DATA);
                MultiValueMap<String, Object> bodyWorker = new LinkedMultiValueMap<>();
                bodyWorker.add("image", base64Image);
                HttpEntity<MultiValueMap<String, Object>> requestEntityWorker = new HttpEntity<>(bodyWorker, headersWorker);

                restTemplate.exchange(
                        urlSetWorkerAttr,
                        HttpMethod.POST,
                        requestEntityWorker,
                        Void.class
                );

                if (numeroPage != null) {
                    String position = numeroPage.toString();
                    String urlSetWorkerAttrPage = prop.getProperty("url_access") + "setWorkerAttributesPage/" + idWorker + "/" + numeroPage;
                    HttpHeaders headers3 = new HttpHeaders();
                    headers3.setContentType(MediaType.APPLICATION_JSON);
                    HttpEntity<Void> requestEntity = new HttpEntity<>(headers3);
                    restTemplate.exchange(
                            urlSetWorkerAttrPage,
                            HttpMethod.POST,
                            requestEntity,
                            Void.class
                    );
                } else {
                    String position = "Last";
                    String urlSetWorkerAttrPage = prop.getProperty("url_access") + "setWorkerAttributesPage/" + idWorker + "/" + position;
                    HttpHeaders headers3 = new HttpHeaders();
                    headers3.setContentType(MediaType.APPLICATION_JSON);
                    HttpEntity<Void> requestEntity = new HttpEntity<>(headers3);
                    restTemplate.exchange(
                            urlSetWorkerAttrPage,
                            HttpMethod.POST,
                            requestEntity,
                            Void.class
                    );
                }

                String urlSetWorkerAttrCoord = prop.getProperty("url_access") + "setWorkerAttributesCoord/" + idWorker;
                HttpHeaders headers4 = new HttpHeaders();
                headers4.setContentType(MediaType.APPLICATION_JSON);
                HttpEntity<Void> requestEntityCoord = new HttpEntity<>(headers4);
//                ResponseEntity<Void> response = restTemplate.exchange(
//                        urlSetWorkerAttrCoord,
//                        HttpMethod.POST,
//                        requestEntityCoord,
//                        Void.class
//                );
                String reloadWorker = prop.getProperty("url_access") + "reloadWorker/" + idWorker;
                HttpHeaders headersReload = new HttpHeaders();
                headers4.setContentType(MediaType.APPLICATION_JSON);
                HttpEntity<Void> requestEntityReload = new HttpEntity<>(headersReload);
                ResponseEntity<Void> response = restTemplate.exchange(
                        reloadWorker,
                        HttpMethod.POST,
                        requestEntityReload,
                        Void.class
                );

                // System.out.println("clee de sign :"+signataireV2.getSignerKey());
                rsp = port.processData(String.valueOf(workerId), null, signedDocumentBytes);
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

    DataResponse rsp2 = null;

    /// ///////////////////////////////DOUBLE SIGNATURE////////////////////////////////////
    @PostMapping("co_signature/{id_signer}")
    @ApiOperation(value = "Cette opération permet la co-signature d'un document par deux intervenants. Le document pdf à signer est envoyé sous format de tableau de bytes (binaire).")
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
            @ApiImplicitParam(name = "id_signer", value = "L'id du premier intervenant.", dataType = "int", paramType = "path", example = "456"),
            @ApiImplicitParam(name = "orgId", value = "L'id du deuxième intervenant.", dataType = "int", paramType = "query", example = "45")
    })
    public ResponseEntity<?> double_ignature_base2(
            @ApiParam(value = "ID de l'application appelante fourni par GAINDE 2000.") @RequestParam(value = "workerId", required = false) Integer idWorker,
            @ApiParam(value = "Le document PDF à signer sous format tableau de bytes.") @RequestParam("filereceivefile") MultipartFile file,
            @ApiParam(value = "Code pour activer les informations du signataire sur le serveur de signature.") @RequestParam("codePin") String codePin,
            @RequestParam(value = "orgId", required = false) Integer orgId,
            @ApiParam(value = "Numéro unique d'enrôlement du signataire.") @PathVariable Integer id_signer) throws IOException {
        logger.info("################Debut de traitement de la signature#########################");
        if (orgId == null) {
            //System.out.println("TESTT");
            logger.error("Erreur lors de la signature : ID du second intervenant doit être renseigné !");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("ID du second intervenant doit être renseigné !");
        }
        if (idWorker == null) {
            logger.error("Erreur lors de la signature : ID Application introuvable !");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("ID Application introuvable !");
        }
        int compteurErreur = 0;
        String datePart1 = "";
        String nomSignataire = "";
        String userkey = "";
        String userkey_signer = "";
        RestTemplate restTemplate = new RestTemplate();
        String urlAccessBdd = prop.getProperty("url_access");
        String url_signer = urlAccessBdd + "findSignerById/" + id_signer;
        String url_signataire = urlAccessBdd + "findSignataireById/" + id_signer;
        String url2 = urlAccessBdd + "ajoutOperation";
        String url3 = urlAccessBdd + "isExistedWorker/" + idWorker;
        String urlOrgId = urlAccessBdd + "findSignerById/" + orgId;
        String urlNomWorker = urlAccessBdd + "findNomWorkerById/" + idWorker;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        try {
            Signataire_V2 signataireV2 = restTemplate.getForObject(url_signer, Signataire_V2.class);
            Signataire_V2 signataireV2_org = restTemplate.getForObject(urlOrgId, Signataire_V2.class);
            Signataire signataire = restTemplate.getForObject(url_signataire, Signataire.class);
            boolean verifWoker = Boolean.TRUE.equals(restTemplate.getForObject(url3, Boolean.class));

            int workerId = idWorker != null ? idWorker.intValue() : 0;
            if (signataireV2 == null && signataire == null) {
                logger.error("Erreur lors de la signature : Utilisateur inconnu !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Utilisateur inconnu !");
            }

            if (signataireV2 != null && signataireV2_org != null) {
                //System.out.println("TESTV2");

                if (!encrypterPin(codePin).equals(signataireV2.getCodePin())) {
                    logger.info("Code pin lors de la signature: " + signataireV2.getCodePin());
                    compteurErreur++;
                } else {
                    compteurErreur = 3;
                    userkey = signataireV2.getSignerKey();
                    userkey_signer = signataireV2_org.getSignerKey();
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
                String reloadWorker = prop.getProperty("url_access") + "reloadWorker/" + idWorker;
                HttpHeaders headersReload = new HttpHeaders();
                headersReload.setContentType(MediaType.APPLICATION_JSON);
                HttpEntity<Void> requestEntityReload = new HttpEntity<>(headersReload);
                ResponseEntity<Void> response = restTemplate.exchange(
                        reloadWorker,
                        HttpMethod.POST,
                        requestEntityReload,
                        Void.class
                );
                try {
                    setupTLS(port, password, userkey_signer.substring(8));
                    //  System.out.println("#####PORT "+userkey.substring(8));
                } catch (IOException | GeneralSecurityException e1) {
                    // TODO Auto-generated catch block
                    //log.error(e1.getMessage());
                    e1.printStackTrace();
                }
                rsp2 = port.processData(String.valueOf(workerId), null, rsp.getData());
                OperationSignature operationSignature = new OperationSignature();
                HttpHeaders headers2 = new HttpHeaders();
                headers2.setContentType(MediaType.APPLICATION_JSON);
                operationSignature.setIdSigner(id_signer);
                operationSignature.setCodePin(signataireV2.getCodePin());
                operationSignature.setSignerKey(signataireV2.getSignerKey());
                operationSignature.setIdCoSigner(orgId);
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

            return ResponseEntity.ok(rsp2.getData());
        } catch (Exception e) {
            String errorMessage = "Une erreur est survenue lors de la signature : " + e.getMessage();
            logger.error(errorMessage, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
        }

    }

    @ApiOperation(value = "Récupère un QR code selon l'id", notes = "Cette opération permet de récupérer un QR code associé à un identifiant donné.")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "QR code récupéré avec succès", response = QrCode.class),
            @ApiResponse(code = 404, message = "Erreur : QR code introuvable"),
            @ApiResponse(code = 500, message = "Erreur interne du serveur")
    })
    @ApiImplicitParams({
            @ApiImplicitParam(name = "idQrCode", value = "ID du QR code à récupérer", required = true, dataType = "long", paramType = "path", example = "12345")
    })
    @GetMapping("getQrCode/{idQrCode}")
    public ResponseEntity<?> getQrCode(@PathVariable Long idQrCode) {
        try {
            logger.info("Appel de l'appel pour récupérer QR code.");
            RestTemplate restTemplate = new RestTemplate();

            // Passer l'ID dans l'URL pour appeler correctement l'API distante
            String urlQrCode = prop.getProperty("url_qrCode") + "getQrCode/" + idQrCode;

            // Afficher l'URL pour le débogage
            System.out.println("URL API : " + urlQrCode);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            // Appeler l'API distante et récupérer la réponse
            ResponseEntity<QrCode> responseEntityQrCode = restTemplate.getForEntity(urlQrCode, QrCode.class);

            // Si la réponse est correcte (200) avec un corps, retourner les données
            if (responseEntityQrCode.getStatusCode().is2xxSuccessful() && responseEntityQrCode.getBody() != null) {
                logger.info("QR code récupéré avec succès");
                return ResponseEntity.ok(responseEntityQrCode.getBody());
            } else {
                // Si le QR code n'est pas trouvé, renvoyer une réponse 404
                logger.warn("QR code introuvable");
                return ResponseEntity.status(404).body("Erreur : QR code introuvable.");
            }

        } catch (HttpClientErrorException.NotFound e) {
            logger.error("QR code introuvable.", e);
            // Gestion spécifique pour une erreur 404
            return ResponseEntity.status(404).body("Erreur : QR code introuvable.");
        } catch (HttpServerErrorException e) {
            logger.error("Erreur du serveur.", e);
            // Gestion des erreurs 500 de l'API externe
            return ResponseEntity.status(500).body("Erreur du serveur.");
        } catch (Exception e) {
            logger.error("Erreur du serveur.", e);
            // Gestion d'autres erreurs
            e.printStackTrace();
            return ResponseEntity.status(500).body("Erreur interne du serveur. Veuillez réessayer plus tard.");
        }
    }

    @GetMapping("getInfosEnrolement")
    public ResponseEntity<?> getInfosEnrolement() {
        String url = prop.getProperty("url_access") + "getInfosEnrolement";

        if (url == null || url.isEmpty()) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("URL d'accès non définie dans les propriétés.");
        }

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        try {
            // Appel de l'API distante avec un tableau comme type attendu
            ResponseEntity<InfosCertificat[]> responseEntityQrCode =
                    restTemplate.getForEntity(url, InfosCertificat[].class);

            InfosCertificat[] body = responseEntityQrCode.getBody();

            return ResponseEntity.status(responseEntityQrCode.getStatusCode())
                    .body(body);

        } catch (RestClientException e) {
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body("Erreur lors de l'appel à l'API distante : " + e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Une erreur inattendue s'est produite : " + e.getMessage());
        }
    }


    @PostMapping("creerSignerStartup")
    public ResponseEntity<String> creerSignerStartupProxy(@RequestBody SignerStartup signerStartup) {
        String url = prop.getProperty("url_access") + "creerSignerStartup";
        RestTemplate restTemplate = new RestTemplate();

        try {
            logger.info("Appel du service creerSignerStartup via RestTemplate pour ID Worker: {}", signerStartup.getIdWorker());

            // Préparer les headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            // Créer la requête
            HttpEntity<SignerStartup> requestEntity = new HttpEntity<>(signerStartup, headers);

            // Appeler le service via RestTemplate
            ResponseEntity<String> response = restTemplate.exchange(
                    url,
                    HttpMethod.POST,
                    requestEntity,
                    String.class
            );

            logger.info("Réponse reçue du service creerSignerStartup : {}", response.getBody());

            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());

        } catch (Exception e) {
            logger.error("Erreur lors de l'appel du service creerSignerStartup", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erreur lors de l'appel du service: " + e);
        }
    }


    @GetMapping("request-code")
    public ResponseEntity<String> requestAuthorizationCode(@RequestParam String redirect_uri) {
        // Construire l'URL pour la demande de code
        String url = prop.getProperty("trustedx_url") + "/trustedx-authserver/oauth/main-as";

        // Créer l'en-tête d'autorisation
        String apiKey = Base64.getEncoder().encodeToString((prop.getProperty("trustedx_clientId") + ":" + prop.getProperty("trustedx_clientPassword")).getBytes(StandardCharsets.UTF_8));
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + apiKey);

        // Ajouter les paramètres de requête
        String params = String.format("response_type=code&client_id=%s&redirect_uri=%s",
                prop.getProperty("trustedx_clientId"), redirect_uri);

        // Effectuer la requête
        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<String> entity = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(url + "?" + params, HttpMethod.GET, entity, String.class);

        // Retourner la réponse
        return ResponseEntity.ok(response.getBody());
    }

    @PostMapping("save-code")
    public ResponseEntity<String> saveCode(@RequestBody String code) {
        String filePath = "D:\\code.txt";

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath, true))) {
            writer.write(code);
            writer.newLine();
            return ResponseEntity.ok("Code enregistré avec succès !");
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Erreur lors de l'enregistrement du code : " + e.getMessage());
        }
    }

    @GetMapping("code_recu")
    public String redirectToIndex(@RequestParam String code) {
        saveCode(code);
        return "Ok code : " + code;
    }

    @GetMapping("qrcode")
    public String showQrCodePage() {
        return "redirect:/qrcode.html"; // Il redirigera vers la page qrcode.html
    }

    public String calculerDateExpirationJours(String dateString) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime initialDate = LocalDateTime.parse(dateString, formatter);

        // Ajoutez une semaine à la date initiale
        LocalDateTime resultDate = initialDate.plusWeeks(Long.parseLong(prop.getProperty("expiration_certificat")));

        // Formatez la date résultante pour l'affichage
        return resultDate.format(formatter);
    }

    public String decouper_nom(String nomAChanger) {
        //System.out.println("1er caractere : "+nomAChanger.charAt(0));
        if (nomAChanger.contains(" ")) {
            String[] caract = nomAChanger.split("\\s+");
            logger.info("Caracteres du tableau :"+caract.toString());
            if (caract.length < 1) {
                return "Tableau vide!";
            }
            if (caract[0].trim().isEmpty()) {
                return "Tableau vide!";
            }
            nomAChanger = caract[0] + "_";
            logger.info("caract de 0 :"+caract[0]);
            logger.info("Taille du tableau :"+caract.length);
            if (caract.length > 1) {
                for (int i = 1; i < caract.length; i++) {
                    logger.info("Dans la boucle FOR");
                    if (!caract[i].trim().isEmpty()) {
                        logger.info("caract de "+i+" :"+caract[i]);
                        nomAChanger += caract[i].charAt(0);
                    }
                }
            }

        }
        if (nomAChanger.length() > 70) {
            nomAChanger = nomAChanger.substring(0, 70);
        }
        logger.info("Nom caractere :"+nomAChanger);
        return nomAChanger;
    }


    @PostMapping("verifications_infos/{id_signer}/{codePin}/{idWorker}")
    public ResponseEntity<?> verificationInformations(@PathVariable Integer id_signer, @PathVariable String codePin, @PathVariable Integer idWorker) {
        int compteurErreur2 = 0;
        RestTemplate restTemplate = new RestTemplate();
        String urlAccessBdd = prop.getProperty("url_access");
        String url_signer = urlAccessBdd + "findSignerById/" + id_signer;
        String url_signataire = urlAccessBdd + "findSignataireById/" + id_signer;
        String url3 = urlAccessBdd + "isExistedWorker/" + idWorker;
        Signataire_V2 signataireV2 = restTemplate.getForObject(url_signer, Signataire_V2.class);
        Signataire signataire = restTemplate.getForObject(url_signataire, Signataire.class);
        boolean verifWoker = Boolean.TRUE.equals(restTemplate.getForObject(url3, Boolean.class));

        if (signataireV2 == null && signataire == null) {
            logger.error("Erreur lors de la signature : Utilisateur inconnu !");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Utilisateur inconnu !");
        }
        if (signataireV2 != null) {
            System.out.println("TESTV2");

            if (!encrypterPin(codePin).equals(signataireV2.getCodePin())) {
                System.out.println("TESTCodePin");
                logger.info("Code pin lors de la signature: " + signataireV2.getCodePin());
                compteurErreur2++;
            }
        }
        if (signataire != null) {
            System.out.println("TESTV1");

            if (!encrypterPin(codePin).equals(signataire.getCode_pin())) {
                logger.info("Code pin lors de la signature: " + signataire.getCode_pin());
                compteurErreur2++;
            }
        }

        if (compteurErreur2 != 0) {
            System.out.println("compteur " + compteurErreur2);
            logger.error("Erreur lors de la signature : Mauvais Code PIN !");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Veuillez fournir un bon code PIN !");
        }

        if (!verifWoker) {
            logger.error("Erreur lors de la signature : ID Application introuvable !");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("ID Application introuvable !");
        }
        return ResponseEntity.status(HttpStatus.OK).body("Les informations saisies sont correctes!");
    }

    public static SubjectPublicKeyInfo getSubjectPublicKeyInfo(X509Certificate certificate) throws CertificateEncodingException, IOException, javax.security.cert.CertificateEncodingException {
        // Obtenir l'encodage DER du certificat
        byte[] encodedCertificate = certificate.getEncoded();

        // Créer un flux d'entrée à partir de l'encodage
        ByteArrayInputStream bis = new ByteArrayInputStream(encodedCertificate);

        // Créer un flux d'entrée ASN.1
        ASN1InputStream dis = new ASN1InputStream(bis);

        // Lire la séquence ASN.1 du certificat
        org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(dis.readObject());

        // Obtenir SubjectPublicKeyInfo
        return cert.getSubjectPublicKeyInfo();
    }

    public static String getSHA256FingerprintAsString(byte[] in) {
        byte[] res = generateSHA256Fingerprint(in);
        return new String(Hex.encode(res));
    }
    public static byte[] generateSHA256Fingerprint(byte[] ba) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(ba);
        } catch (NoSuchAlgorithmException nsae) {
            //log.error("SHA-256 algorithm not supported", nsae);
        }
        return null;
    } // generateSHA256Fingerprint


    public static String concatenateAsciiCodes(String input) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            result.append((int) c); // Convertir en code ASCII et concaténer
        }
        return result.toString();
    }


    public String calculateUidCert(HttpServletRequest request) throws Exception {
        X509Certificate[] certs = (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");

        X509Certificate certif_client= certs[0];


        SubjectPublicKeyInfo publicKeyInfo = new JcaX509CertificateHolder(certif_client).getSubjectPublicKeyInfo();
        byte[] keyBytes = publicKeyInfo.getPublicKeyData().getBytes();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(keyBytes);

        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }

    public static X509Certificate convertStringToX509(String pemCert) throws Exception {

        // Décoder la chaîne Base64 en tableau de bytes
        byte[] certBytes = Base64.getDecoder().decode(pemCert);

        // Convertir en certificat X.509
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    // calcul de la durée d'exécution
    private void logDuration(String stepName, long start) {
        long end = System.currentTimeMillis();
        logger.info("Durée étape [" + stepName + "] : " + (end - start) + " ms");
    }
}
