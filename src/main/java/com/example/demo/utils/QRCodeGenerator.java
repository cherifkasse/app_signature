package com.example.demo.utils;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.text.PDFTextStripperByArea;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class QRCodeGenerator {
    public static byte[] generateQRCodeImage(String text, int width, int height) throws WriterException, IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height);
        BufferedImage bufferedImage = MatrixToImageWriter.toBufferedImage(bitMatrix);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(bufferedImage, "png", baos);
        return baos.toByteArray();
    }

    // Trouver une zone libre sur la page
    public static Rectangle findFreeAreaOnPage(PDPage page, int width, int height) throws IOException {
        PDFTextStripperByArea stripper = new PDFTextStripperByArea();
        int pageWidth = (int) page.getMediaBox().getWidth();
        int pageHeight = (int) page.getMediaBox().getHeight();

        // Diviser la page en une grille de zones à vérifier
        int stepX = 50; // Largeur d'une zone
        int stepY = 50; // Hauteur d'une zone

        for (int x = 0; x <= pageWidth - width; x += stepX) {
            for (int y = 0; y <= pageHeight - height; y += stepY) {
                Rectangle rect = new Rectangle(x, y, width, height);
                stripper.addRegion("test", rect);
                stripper.extractRegions(page);
                String text = stripper.getTextForRegion("test").trim();

                // Vérifier si la zone est libre de texte
                if (text.isEmpty()) {
                    return rect; // Retourner la première zone libre trouvée
                }
            }
        }
        return null; // Pas de zone libre trouvée
    }
}
