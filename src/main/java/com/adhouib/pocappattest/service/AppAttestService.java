package com.adhouib.pocappattest.service;

import com.adhouib.pocappattest.Constants;
import com.upokecenter.cbor.CBORObject;
import jakarta.annotation.PostConstruct;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Base64.Decoder;
import java.util.Collections;
import java.util.List;

@Service
public class AppAttestService {

    private final Decoder base64Decoder = java.util.Base64.getDecoder();

    @PostConstruct
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public boolean validateAttestation(String attestationObjectB64, String clientDataHashB64) {
        try {
            byte[] attestationObjectBytes = base64Decoder.decode(attestationObjectB64);
            CBORObject attestation = CBORObject.DecodeFromBytes(attestationObjectBytes);

            // 1. Parse CBOR
            CBORObject fmt = attestation.get("fmt");
            CBORObject attStmt = attestation.get("attStmt");
            CBORObject authData = attestation.get("authData");

            if (authData == null || attStmt == null) return false;

            byte[] authenticatorData = authData.GetByteString();

            // 2. Get and verify nonce
            byte[] clientDataHash = base64Decoder.decode(clientDataHashB64);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(authenticatorData);
            digest.update(clientDataHash);
            byte[] computedNonce = digest.digest();

            byte[] nonceFromCert = getNonceFromCert(attStmt);
            if (!Arrays.equals(computedNonce, nonceFromCert)) {
                return false;
            }

            // 3. Validate certificate chain
            List<X509Certificate> certChain = getCertificates(attStmt);
            validateCertChain(certChain);

            // 4. Optional: Extract public key and credential ID
            String publicKey = Base64.encodeBase64String(getCredentialPublicKeyFromAuthData(authenticatorData));
            System.out.println("Extracted Public Key: " + publicKey);

            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private byte[] getNonceFromCert(CBORObject attStmt) throws Exception {
        CBORObject certs = attStmt.get("x5c");
        byte[] certBytes = certs.get(0).GetByteString();
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
        byte[] ext = cert.getExtensionValue("1.2.840.113635.100.8.2");
        if (ext == null) throw new CertificateParsingException("Nonce extension not found in certificate.");
        // parse OCTET STRING inside
        return parseASN1OctetString(ext);
    }

    private byte[] extractNonceFromExtension(X509Certificate cert) throws Exception {
        byte[] extVal = cert.getExtensionValue("1.2.840.113635.100.8.2");
        if (extVal == null) throw new IllegalStateException("Nonce extension not found");

        // Parse outer DER OCTET STRING
        ByteArrayInputStream in = new ByteArrayInputStream(extVal);
        int tag = in.read(); // usually 0x04
        int len = in.read(); // length
        if (len == 0x81) len = in.read(); // handle extended lengths

        byte[] inner = in.readNBytes(len);

        // Parse inner again (nested OCTET STRING)
        ByteArrayInputStream in2 = new ByteArrayInputStream(inner);
        int tag2 = in2.read(); // 0x04
        int len2 = in2.read();
        if (len2 == 0x81) len2 = in2.read(); // handle extended again

        return in2.readNBytes(len2);
    }

    private List<X509Certificate> getCertificates(CBORObject attStmt) throws CertificateException {
        CBORObject certs = attStmt.get("x5c");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return List.of(
                (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(certs.get(0).GetByteString())),
                (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(certs.get(1).GetByteString()))
        );
    }

    private void validateCertChain(List<X509Certificate> certs) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate rootCA = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(Constants.ROOT_CA.getBytes()));

        CertPath certPath = cf.generateCertPath(certs);
        TrustAnchor anchor = new TrustAnchor(rootCA, null);
        PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
        params.setRevocationEnabled(false);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        validator.validate(certPath, params);
    }

    private byte[] getCredentialPublicKeyFromAuthData(byte[] authData) {
        int offset = 37; // skip RP ID hash (32), flags (1), signCount (4)
        int aaguidLen = 16;
        int credIdLen = ByteBuffer.wrap(authData, offset + aaguidLen, 2).getShort();
        offset += aaguidLen + 2 + credIdLen;
        return Arrays.copyOfRange(authData, offset, authData.length);
    }

    private byte[] parseASN1OctetString(byte[] encoded) throws Exception {
        // Drop first 4 bytes (DER OCTET STRING prefix)
        int offset = 4;
        return Arrays.copyOfRange(encoded, offset, encoded.length);
    }
}
