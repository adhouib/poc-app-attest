package com.adhouib.pocappattest.repository;

import com.adhouib.pocappattest.model.AppAttestationEntity;
import com.adhouib.pocappattest.model.DeviceNonce;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AppAttestationRepository extends JpaRepository<AppAttestationEntity, String> {
    Optional<AppAttestationEntity> findAppAttestationEntityByDeviceId(String deviceId);
    // Tu peux ajouter des méthodes personnalisées si nécessaire
}
