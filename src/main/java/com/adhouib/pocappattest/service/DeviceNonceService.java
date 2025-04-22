package com.adhouib.pocappattest.service;

import com.adhouib.pocappattest.model.AppAttestationEntity;
import com.adhouib.pocappattest.model.DeviceNonce;
import com.adhouib.pocappattest.repository.AppAttestationRepository;
import com.adhouib.pocappattest.repository.DeviceNonceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

@RequiredArgsConstructor
@Service
public class DeviceNonceService {
    private final AppAttestationRepository appAttestationRepository;

    private static final int CHALLENGE_LENGTH = 32;
    private static final Duration TTL = Duration.ofMinutes(5);

    // Fonction pour générer un nonce sécurisé
    public byte[] generateNonce() {
        byte[] challenge = new byte[CHALLENGE_LENGTH];
        new SecureRandom().nextBytes(challenge);
        return challenge;
    }

    // Fonction pour générer et sauvegarder le nonce dans la base de données avec le device ID
    public AppAttestationEntity generateAndSaveNonce(String deviceId) {
        byte[] nonce = generateNonce();


        AppAttestationEntity entity = new AppAttestationEntity();
        entity.setDeviceId(deviceId);
        entity.setNonce(nonce);
        entity.setCreatedAt(Instant.now());
        entity.setChallengeVerified(false);


        return appAttestationRepository.save(entity);
    }
}
