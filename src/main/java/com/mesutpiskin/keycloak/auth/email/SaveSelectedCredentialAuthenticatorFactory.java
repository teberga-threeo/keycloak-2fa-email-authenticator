package com.mesutpiskin.keycloak.auth.email;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;
import java.util.Set;

public class SaveSelectedCredentialAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "selected-credential-authenticator";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Selected Credential Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void init(org.keycloak.Config.Scope scope) {
    }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

	@Override
	public Authenticator create(KeycloakSession session) {
        return new SaveSelectedCredentialAuthenticator();
	}

	@Override
	public String getHelpText() {
        return "Captura o campo selectedCredential do form e salva no AuthNote para uso posterior";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return Collections.emptyList();
	}
}
