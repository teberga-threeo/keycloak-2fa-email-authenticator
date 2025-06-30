package com.mesutpiskin.keycloak.auth.email;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import java.util.List;

public class Select2faMethodAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "select-2fa-method-authenticator";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "Select 2FA Method";
    }

    @Override
    public String getHelpText() {
        return "Allows the user to select between Email or App OTP based on their configuration.";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new Select2faMethodAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
        // No initialization needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post initialization needed
    }

    @Override
    public void close() {
        // No cleanup necessary
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[]{
            Requirement.REQUIRED,
            Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        // This authenticator doesn't support per-user setup
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        // No configuration properties
        return null;
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }
}
