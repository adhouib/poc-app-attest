package com.adhouib.pocappattest.tools;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class DummyAttestationGenerator {

    public static void main(String[] args) throws Exception {
        // 1. Generate ECDSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 2. Load dummy Apple cert (corresponds to publicKey)
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        InputStream certStream = DummyAttestationGenerator.class.getClassLoader().getResourceAsStream("static/Apple_App_Attestation_Root_CA.pem");

        if (certStream == null) {
            throw new RuntimeException("❌ Apple Root CA not found in resources folder!");
        }

        X509Certificate dummyCert = (X509Certificate) certFactory.generateCertificate(certStream);


        byte[] certBytes = dummyCert.getEncoded();

        // 3. Create mock authData and clientDataHash
        byte[] authData = "mock-auth-data".getBytes(); // normally WebAuthn packed format
        byte[] clientDataHash = "mock-client-hash".getBytes();

        // 4. Sign authData + clientDataHash
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        sig.update(concat(authData, clientDataHash));
        byte[] signature = sig.sign();

        // 5. Create CBOR object: { "authData": ..., "fmt": "apple", "attStmt": { "sig": ..., "x5c": [...] } }
        Map<String, Object> attStmt = new LinkedHashMap<>();
        attStmt.put("sig", signature);
        attStmt.put("x5c", Collections.singletonList(certBytes));

        Map<String, Object> attestationObject = new LinkedHashMap<>();
        attestationObject.put("authData", authData);
        attestationObject.put("fmt", "apple");
        attestationObject.put("attStmt", attStmt);

        // 6. Encode as CBOR and base64
        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper cborMapper = new ObjectMapper(cborFactory);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        cborMapper.writeValue(baos, attestationObject);

        byte[] cborBytes = baos.toByteArray();
        String base64AttestationObject = Base64.getEncoder().encodeToString(cborBytes);
        String base64ClientDataHash = Base64.getEncoder().encodeToString(clientDataHash);

        // Output values for testing
        System.out.println("attestationObject: " + base64AttestationObject);
        System.out.println("clientDataHash: " + base64ClientDataHash);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
