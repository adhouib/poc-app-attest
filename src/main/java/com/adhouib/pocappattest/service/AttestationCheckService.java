package com.adhouib.pocappattest.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.Signature;
import java.security.cert.*;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
public class AttestationCheckService {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public boolean verify(String attestationObjectB64, String clientDataHashB64, byte[] expectedNonce,
                          String deviceId, X509Certificate appleRootCACert) throws Exception {
        // Decode base64
        byte[] attestationObject = Base64.getDecoder().decode(attestationObjectB64);
        byte[] clientDataHash = Base64.getDecoder().decode(clientDataHashB64);

        // Decode CBOR
        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper mapper = new ObjectMapper(cborFactory);
        Map<String, Object> attObj = mapper.readValue(attestationObject, Map.class);

        byte[] authData = (byte[]) attObj.get("authData");
        Map<String, Object> attStmt = (Map<String, Object>) attObj.get("attStmt");
        byte[] signature = (byte[]) attStmt.get("sig");

        List<byte[]> x5c = (List<byte[]>) attStmt.get("x5c");
        if (x5c == null || x5c.isEmpty()) throw new SecurityException("Missing certificate chain");

        // Load cert
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate leafCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(x5c.get(0)));

        // Check certificate chain
        CertPath path = certFactory.generateCertPath(Collections.singletonList(leafCert));
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(appleRootCACert, null)));
        params.setRevocationEnabled(false);

        validator.validate(path, params);

        // Check Apple OID extension 1.2.840.113635.100.8.2
        boolean found = false;
        for (String oid : leafCert.getNonCriticalExtensionOIDs()) {
            if ("1.2.840.113635.100.8.2".equals(oid)) {
                found = true;
                break;
            }
        }
        if (!found) throw new SecurityException("Missing Apple AppAttest OID");

        // Verify signature
        byte[] signedData = concat(authData, clientDataHash);
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(leafCert.getPublicKey());
        sig.update(signedData);

        return sig.verify(signature);
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
