package com.adhouib.pocappattest.controller;
import com.adhouib.pocappattest.model.AssertionRequest;
import com.adhouib.pocappattest.model.DeviceNonce;
import com.adhouib.pocappattest.service.AppAttestationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

@RestController
public class AssertionController {

    private final AppAttestationService appAttestationService;

    public AssertionController(AppAttestationService appAttestationService) {
        this.appAttestationService = appAttestationService;
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
