package com.adhouib.pocappattest.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AssertionRequest {
    private String deviceId;

    // Base64-encoded values envoyés par l'app iOS
    private String assertion;           // Signature AppAttest
    private String clientDataHash;      // SHA256(nonce ou challenge)
    private String authenticatorData;   // AuthenticatorData brut (CBOR)
}
