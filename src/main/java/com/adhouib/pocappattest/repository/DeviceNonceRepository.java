package com.adhouib.pocappattest.repository;

import com.adhouib.pocappattest.model.DeviceNonce;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DeviceNonceRepository extends JpaRepository<DeviceNonce, Long> {
    Optional<DeviceNonce> findDeviceNonceByDeviceId(String deviceId);
    // Tu peux ajouter des méthodes personnalisées si nécessaire
}
