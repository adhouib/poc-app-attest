package com.adhouib.pocappattest.service;

import com.adhouib.pocappattest.model.AppAttestationEntity;
import com.adhouib.pocappattest.repository.AppAttestationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

@Service
@RequiredArgsConstructor
public class AppAttestationService {

    private final AppAttestationRepository repository;

    public boolean verifyAssertion(String deviceId, byte[] assertion, byte[] clientDataHash, byte[] authenticatorData) {
        AppAttestationEntity entity = repository.findById(deviceId)
                .orElseThrow(() -> new IllegalArgumentException("Device ID not found in database"));

        try {
            byte[] publicKeyBytes = entity.getPublicKey();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(spec);

            // concat(authData + clientDataHash)
            byte[] toVerify = new byte[authenticatorData.length + clientDataHash.length];
            System.arraycopy(authenticatorData, 0, toVerify, 0, authenticatorData.length);
            System.arraycopy(clientDataHash, 0, toVerify, authenticatorData.length, clientDataHash.length);

            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(publicKey);
            sig.update(toVerify);

            return sig.verify(assertion);
        } catch (Exception e) {
            throw new RuntimeException("Erreur lors de la vérification de l'assertion", e);
        }
    }
}
