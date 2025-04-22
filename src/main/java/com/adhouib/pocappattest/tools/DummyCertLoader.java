package com.adhouib.pocappattest.tools;


import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class DummyCertLoader {

    public static void main(String[] args) throws Exception {
        InputStream pemStream = DummyCertLoader.class
                .getClassLoader()
                .getResourceAsStream("static/Apple_App_Attestation_Root_CA.pem");

        if (pemStream == null) {
            throw new RuntimeException("❌ Fichier PEM non trouvé !");
        }

        String pem = new String(pemStream.readAllBytes(), StandardCharsets.UTF_8);

        // Extraire la partie base64
        String base64 = pem
                .replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", ""); // supprimer tous les retours à la ligne

        // Décoder en DER
        byte[] certBytes = Base64.getDecoder().decode(base64);

        // Lire le certificat DER
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certBytes)
        );

        System.out.println("✅ Certificat chargé : " + cert.getSubjectX500Principal());
    }
}
