package com.adhouib.pocappattest.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class AppAttestationEntity {

    @Id
    private String deviceId;

    @Lob
    private byte[] nonce;

    private Instant createdAt;

    private boolean challengeVerified;

    @Lob
    private byte[] publicKey; // clé publique extraite depuis la clé App Attest
}
