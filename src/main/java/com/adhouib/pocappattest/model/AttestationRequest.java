package com.adhouib.pocappattest.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AttestationRequest {
    private String deviceId;
    private String attestationObject;
    private String clientDataHash;

    // Getters & Setters
}
