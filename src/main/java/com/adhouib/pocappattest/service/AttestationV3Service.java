package com.adhouib.pocappattest.service;


import com.adhouib.pocappattest.model.AttestationRequestV3;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorAttestationResponse;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
public class AttestationV3Service {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);

    public boolean validateAttestation(AttestationRequestV3 request) {
        try {
            byte[] attestationObjectBytes = Base64.getUrlDecoder().decode(request.attestationObjectBase64);
            byte[] clientDataHash = Base64.getUrlDecoder().decode(request.clientDataHashBase64);

            AuthenticatorAttestationResponse attestationResponse =
                    new AuthenticatorAttestationResponse(attestationObjectBytes, clientDataHash);

            //RegistrationRequest registrationRequest = new RegistrationRequest(attestationResponse);
            RegistrationRequest registrationRequest = new RegistrationRequest(attestationObjectBytes, clientDataHash);
            RegistrationParameters registrationParameters = new RegistrationParameters(null, false);

            webAuthnManager.validate(registrationRequest, registrationParameters);
            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

}
