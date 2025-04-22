package com.adhouib.pocappattest.service;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class AttestationCheckServiceTest {

    @Test
    public void testVerifyWithMockData() throws Exception {
        AttestationCheckService verifier = new AttestationCheckService();

        // Mock base64 attestationObject and clientDataHash
        String attestationObjectBase64 = "o2NmbXQuaXJ..."; // truncate
        String clientDataHashBase64 = Base64.getEncoder().encodeToString("fakeHash==".getBytes(StandardCharsets.UTF_8));
        byte[] expectedNonce = "expectedNonce".getBytes(StandardCharsets.UTF_8);
        String deviceId= "";

        // Load Apple Root CA (needs to be added to test/resources)
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate appleRootCA = (X509Certificate) certFactory.generateCertificate(
                getClass().getClassLoader().getResourceAsStream("static/Apple_App_Attestation_Root_CA.pem")
        );

        // Should fail with mock data
        assertThrows(Exception.class, () ->
                verifier.verify(attestationObjectBase64, clientDataHashBase64, expectedNonce, deviceId, appleRootCA)
        );
    }
}

