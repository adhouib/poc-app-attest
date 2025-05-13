package com.adhouib.pocappattest.controller;

import com.adhouib.pocappattest.Constants;
import com.adhouib.pocappattest.model.AttestationRequest;
import com.adhouib.pocappattest.service.AppAttestService;
import com.adhouib.pocappattest.service.ChallengeService;
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/appattest/v2")
public class AppAttestV2Controller {

    private final AppAttestService appAttestService;
    private final RestTemplateAutoConfiguration restTemplateAutoConfiguration;
    private final ChallengeService challengeService;

    public AppAttestV2Controller(AppAttestService appAttestService, RestTemplateAutoConfiguration restTemplateAutoConfiguration, ChallengeService challengeService) {
        this.appAttestService = appAttestService;
        this.restTemplateAutoConfiguration = restTemplateAutoConfiguration;
        this.challengeService = challengeService;
    }

    @PostMapping("/init")
    public AttestationRequest initRequest(@RequestParam String deviceId) {
        AttestationRequest attestationRequest = new AttestationRequest();
        attestationRequest.setDeviceId(deviceId);
        attestationRequest.setAttestationObject(Constants.ATTEST_OBJECT);
        attestationRequest.setClientDataHash(Constants.KEY_ID);
        attestationRequest.setChallenge(challengeService.generateAndSaveNonce(deviceId).getNonce());

        return attestationRequest;
    }

    /**
     * POST /appattest/validate
     * Expects:
     * {
     *   "attestationObject": "<base64 attestationObject>",
     *   "clientDataHash": "<base64 clientDataHash>"
     * }
     */
    @PostMapping("/validate")
    public ResponseEntity<String> validateAttestation(@RequestBody Map<String, String> payload) {
        String attestationObject = payload.get("attestationObject");
        String clientDataHash = payload.get("clientDataHash");

        if (attestationObject == null || clientDataHash == null) {
            return ResponseEntity.badRequest().body("attestationObject and clientDataHash are required");
        }

        boolean valid = appAttestService.validateAttestation(attestationObject, clientDataHash);

        if (valid) {
            return ResponseEntity.ok("Attestation is valid.");
        } else {
            return ResponseEntity.status(400).body("Attestation is invalid.");
        }
    }
}
