package com.example.demo.controller;
import  io.swagger.annotations.ApiResponse;
import com.example.demo.model.*;
import com.example.demo.wsdl_client.*;
import io.swagger.annotations.*;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transport.http.auth.HttpAuthHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.*;

import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.http.*;

import springfox.documentation.annotations.ApiIgnore;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * @author Cherif KASSE
 * @project SunuBtrust360_Enrol
 * @created 19/03/2024/03/2024 - 14:48
 */
@RestController
@RequestMapping("/signer/")
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
    public SignerController(){
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
        byte[] keyBytes = hexStringToByteArray(keyString);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }
    private static byte[] hexStringToByteArray(String s) {
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
            SecretKey secretKey = getSecretKey(prop.getProperty("cleDeSecret"));
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
            return replacedString.toString();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                 | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return "Error during encryption.";
        }
    }
    DataResponse rsp=null;
    @PostMapping("sign_document/{id_signer}")
    @ApiOperation(value="Cette opération permet à l'utilisateur de signer un document. Le document pdf à signer est envoyé sous format de tableau de bytes (binaire).")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Le document a été signé avec succès\n\nParamètres de sortie:\n\n" +
                    "\t{\n\n\t    Document signé sous format tableau de bytes\n\n\t}", examples = @Example(@ExampleProperty(mediaType = "application/pdf", value = "extrait du PDF signé"))),
            @ApiResponse(code = 204, message = "Expiration du certificat"),
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
            @ApiParam(value="ID de l'application appelante fourni par GAINDE 2000.") @RequestParam(value="workerId") Integer idWorker,
            @ApiParam(value="Le document PDF à signer sous format tableau de bytes.") @RequestParam("filereceivefile") MultipartFile file,
            @ApiParam(value="Code pour activer les informations du signataire sur le serveur de signature.") @RequestParam("codePin") String codePin,
            @ApiParam(value="Numéro unique d'enrôlement du signataire.") @PathVariable Integer id_signer) throws IOException {
        logger.info("################Début de traitement de la signature#########################");
        int compteurErreur = 0;
        String nomSignataire = "";
        RestTemplate restTemplate = new RestTemplate();
        String urlAccessBdd = prop.getProperty("url_access");
        String url_signer = urlAccessBdd+"findSignerById/"+id_signer;
        String url_signataire = urlAccessBdd+"findSignataireById/"+id_signer;
        String url2 = urlAccessBdd+"ajoutOperation";
        String url3 = urlAccessBdd+"isExistedWorker/"+idWorker;
        try{
            Signataire_V2 signataireV2 = restTemplate.getForObject(url_signer, Signataire_V2.class);
            Signataire signataire = restTemplate.getForObject(url_signataire, Signataire.class);
            boolean verifWoker = Boolean.TRUE.equals(restTemplate.getForObject(url3, Boolean.class));
            if(idWorker == null){
                logger.error("Erreur lors de la signature : ID Application introuvable !");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("ID Application introuvable !");
            }
            int workerId = idWorker != null ? idWorker.intValue() : 0;
            if(signataireV2 == null && signataire == null){
                logger.error("Erreur lors de la signature : Utilisateur inconnu !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Utilisateur inconnu !");
            }

            if(signataireV2 != null){
                System.out.println("TESTV2");

                if (!encrypterPin(codePin).equals(signataireV2.getCodePin())) {
                    compteurErreur++;
                }
                else{
                    nomSignataire = signataireV2.getNomSignataire();
                }
            }

            if(signataire != null){
                System.out.println("TESTV1");

                if (!encrypterPin(codePin).equals(signataire.getCode_pin())) {
                    compteurErreur++;
                }
                else{
                    nomSignataire = signataire.getNomSignataire();
                }
            }
            if(compteurErreur==2){
                logger.error("Erreur lors de la signature : Mauvais Code PIN !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Veuillez fournir un bon code PIN !");
            }

            if (file.isEmpty()) {
                logger.error("Erreur lors de la signature : Fichier introuvable !");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Veuillez selectionner un fichier !");
            }
            if(!verifWoker){
                logger.error("Erreur lors de la signature : ID Application introuvable !");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("ID Application introuvable !");
            }
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);

            //headers.add("X-Keyfactor-Requested-With","");
            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            body.add("filereceivefile", new ByteArrayResource(file.getBytes()){
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
            URL wsdlURL=null;
            try {
                wsdlURL = new URL(serviceURL );
            } catch (MalformedURLException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            ClientWSService service = new ClientWSService(wsdlURL);
            ClientWS port = service.getClientWSPort();
            //System.out.println("#####PORT "+port);
            try {
                setupTLS(port, password, nomSignataire);
            } catch (IOException | GeneralSecurityException e1) {
                // TODO Auto-generated catch block
                //log.error(e1.getMessage());
                e1.printStackTrace();
            }

            try {

                byte[] fileBytes = file.getBytes();
                List<byte[]> bytesFile = new ArrayList<>();
                bytesFile.add(fileBytes);
                rsp= port.processData(String.valueOf(workerId), null, fileBytes);
                OperationSignature operationSignature = new OperationSignature();
                HttpHeaders headers2 = new HttpHeaders();
                headers2.setContentType(MediaType.APPLICATION_JSON);
                operationSignature.setIdSigner(id_signer);
                operationSignature.setCodePin(signataireV2.getCodePin());
                operationSignature.setSignerKey(signataireV2.getSignerKey());
                Date dateOp = new Date();
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                operationSignature.setDateOperation(sdf.format(dateOp));
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

            return ResponseEntity.ok(rsp.getData()) ;
        }
        catch (Exception e) {
            String errorMessage = "Une erreur est survenue lors de la signature : " + e.getMessage();
            logger.error(errorMessage, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
        }

    }
    @PostMapping("enroll")
    @ApiOperation(value="Ce chapitre décrit toutes les opérations exposées par le service de gestion des opérations d’enrôlement d’un signataire. Elle permet à une application d’envoyer les informations nécessaires à l’enrôlement d’un signataire sur le serveur de signature.")
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
        String apiUrl = urlAccess + "enroll";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        try {
            ResponseEntity<Signataire_V2[]> signataireV2 = restTemplate.getForEntity(url, Signataire_V2[].class);
            Signataire_V2[] signatairesArray = signataireV2.getBody();
            assert signatairesArray != null;
            List<Signataire_V2> signatairesList = Arrays.asList(signatairesArray);

            if (!signatairesList.isEmpty()) {
                String conflictMessage = "Person already exists!";
                logger.info(conflictMessage);
                return ResponseEntity.status(HttpStatus.CONFLICT).body(conflictMessage);
            }

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
    //@ApiIgnore

    //////////////////////////////////////////////////////////////

    private void setupTLS(ClientWS port, String keyPassword, String username)
            throws FileNotFoundException, IOException, GeneralSecurityException {

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
    @ApiOperation(value="Cette section permet à l’application métier qui a effectué un enrôlement de téléverser une copie d'un document d'identité pour un signataire existant dans le système. En téléversant une pièce d'identité, les opérateurs du centre d’enregistrement peuvent vérifier et authentifier l'identité du signataire. Cette fonctionnalité améliore les mesures de sécurité et garantit le respect des protocoles de vérification d'identité.")
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
                                                      @RequestParam("piece_cni") @ApiParam(value = "Le document justificatif de la pièce d'identité (photo, pdf, ...) sous format tableau de bytes.") MultipartFile file){
        if (file.isEmpty()) {
            return  ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Fichier non existant !");
        }
        RestTemplate restTemplate = new RestTemplate();
        String urlAccessBdd = prop.getProperty("url_access");
        String url = urlAccessBdd+"depot/"+idSignataire;
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



}
