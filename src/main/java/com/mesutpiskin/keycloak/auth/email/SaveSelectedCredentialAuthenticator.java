package com.mesutpiskin.keycloak.auth.email;

import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.AuthenticatorConfigModel;
import org.jboss.logging.Logger;

public class SaveSelectedCredentialAuthenticator implements Authenticator {

	private static final Logger logger = Logger.getLogger(SaveSelectedCredentialAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        String selectedCredential = formData.getFirst("selectedCredential");

        if (selectedCredential != null) {
            context.getAuthenticationSession().setAuthNote("selectedCredential", selectedCredential);
            logger.infof("selectedCredential capturado: %s", selectedCredential);
        } else {
            logger.warn("selectedCredential não encontrado no formData.");
        }

        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, org.keycloak.models.UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, org.keycloak.models.UserModel user) {

    }

    @Override
    public void close() {
    }
}