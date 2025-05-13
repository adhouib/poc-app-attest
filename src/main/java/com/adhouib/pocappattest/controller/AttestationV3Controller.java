package com.adhouib.pocappattest.controller;

import appatttest.model.AttestationRequest;
import appatttest.service.AttestationService;
import com.adhouib.pocappattest.model.AttestationRequestV3;
import com.adhouib.pocappattest.service.AttestationV3Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/attest")
public class AttestationV3Controller {

    @Autowired
    private AttestationV3Service service;


    @PostMapping
    public String validateAttestation(@RequestBody AttestationRequestV3 request) {
        boolean valid = service.validateAttestation(request);
        return valid ? "Attestation validée" : "Attestation invalide";
    }
}
