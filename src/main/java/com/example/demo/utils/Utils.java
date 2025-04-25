package com.example.demo.utils;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfWriter;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;

public class Utils {
    public static void createPdf(byte[] contentFile,Integer signerId, String userKey,String fileName,Properties properties) throws IOException, DocumentException {
        // Récupérer le chemin du répertoire à partir des propriétés
        String outputDirPath = properties.getProperty("output_directory");
        if (outputDirPath == null || outputDirPath.isEmpty()) {
            throw new IOException("Le chemin du répertoire de sortie n'est pas défini dans le fichier de configuration.");
        }

        // Créer le répertoire s'il n'existe pas
        File outputDir = new File(outputDirPath);
        if (!outputDir.exists() && !outputDir.mkdirs()) {
            throw new IOException("Impossible de créer le répertoire de sortie : " + outputDirPath);
        }

        // Générer le nom du fichier basé sur l'ID, la clé et la date/heure
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String fileName2 = fileName+ timestamp + ".pdf";

        // Chemin complet du fichier PDF
        File pdfFile = new File(outputDir, fileName2);

        // Écrire les bytes du fichier directement dans un fichier
        try (FileOutputStream fos = new FileOutputStream(pdfFile)) {
            fos.write(contentFile);
        }
        catch (IOException e) {
            throw new IOException("Erreur lors de l'écriture du fichier PDF : " + e.getMessage(), e);
        }

        // Création du document PDF
        //Document document = new Document();
        //PdfWriter.getInstance(document, Files.newOutputStream(pdfFile.toPath()));
        //document.open();

        // Ajouter le contenu (bytes du fichier) dans le PDF
        //document.add(new Paragraph("Contenu du fichier en bytes :"));
        //byte[] fileBytes = contentFile;
        //document.add(new Paragraph(new String(fileBytes)));

        //document.close();

        // Retourner le chemin complet du fichier généré

    }
}
