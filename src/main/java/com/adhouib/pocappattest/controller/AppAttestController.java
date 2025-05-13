package com.adhouib.pocappattest.controller;

import com.adhouib.pocappattest.model.AppAttestationEntity;
import com.adhouib.pocappattest.model.AssertionRequest;
import com.adhouib.pocappattest.model.AttestationRequest;
import com.adhouib.pocappattest.repository.AppAttestationRepository;
import com.adhouib.pocappattest.service.AppAttestationService;
import com.adhouib.pocappattest.service.AttestationCheckService;
import com.adhouib.pocappattest.service.ChallengeService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.cert.CertificateFactory;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Base64;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/attest")
public class AppAttestController {

    private final AttestationCheckService verifier;
    private final ChallengeService challengeService;
    private final AppAttestationRepository appAttestationRepository;
    private final AppAttestationService appAttestationService;


    // Endpoint pour générer un nonce et le sauvegarder avec un deviceId
    @PostMapping("/init")
    public AppAttestationEntity generateNonce(@RequestParam String deviceId) {
        return challengeService.generateAndSaveNonce(deviceId);
    }

    @PostMapping("/verify")
    public boolean verifyAttestation(@RequestBody AttestationRequest request) throws Exception {
        // Find nonce associated with deviceId
        AppAttestationEntity deviceNonce = appAttestationRepository.findAppAttestationEntityByDeviceId(request.getDeviceId())
                .orElseThrow(() -> new RuntimeException("Device ID not found"));

        byte[] expectedNonce = Base64.getDecoder().decode(deviceNonce.getNonce());

        // Load Apple App Attestation Root CA
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream certStream = getClass().getClassLoader().getResourceAsStream("static/Apple_App_Attestation_Root_CA.pem");

        if (certStream == null) {
            throw new RuntimeException("Apple Root CA not found in resources");
        }

        X509Certificate appleRootCA = (X509Certificate) certFactory.generateCertificate(certStream);

        // Verify
        return verifier.verify(
                request.getAttestationObject(),
                request.getClientDataHash(),
                expectedNonce,
                request.getDeviceId(),
                appleRootCA
        );
    }

    @PostMapping("/assertion/verify")
    public ResponseEntity<Boolean> verifyAssertion(@RequestBody AssertionRequest request) {
        byte[] assertionBytes = Base64.getDecoder().decode(request.getAssertion());
        byte[] clientDataHashBytes = Base64.getDecoder().decode(request.getClientDataHash());
        byte[] authenticatorDataBytes = Base64.getDecoder().decode(request.getAuthenticatorData());

        boolean isValid = appAttestationService.verifyAssertion(
                request.getDeviceId(),
                assertionBytes,
                clientDataHashBytes,
                authenticatorDataBytes);

        return ResponseEntity.ok(isValid);
    }
}
