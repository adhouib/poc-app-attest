package com.adhouib.pocappattest.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AttestationRequest {
    private String deviceId;
    private String attestationObject;
    private String clientDataHash;
    private byte[] challenge;

    // Getters & Setters
}
