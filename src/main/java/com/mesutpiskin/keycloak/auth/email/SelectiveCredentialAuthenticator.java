package com.mesutpiskin.keycloak.auth.email;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.UserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SelectiveCredentialAuthenticator implements Authenticator {

    private static final Logger logger = LoggerFactory.getLogger(SelectiveCredentialAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String expected = context.getAuthenticatorConfig().getConfig().get("expectedValue");
        String selected = context.getAuthenticationSession().getAuthNote("selectedCredential");

        logger.info("SelectiveCredentialAuthenticator - expectedValue (from config): {}", expected);
        logger.info("SelectiveCredentialAuthenticator - selectedCredential (from screen/session): {}", selected);

        if (expected != null && expected.equals(selected)) {
            context.success();
        } else {
            context.attempted();
        }
    }

    @Override public void action(AuthenticationFlowContext context) {}
    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
