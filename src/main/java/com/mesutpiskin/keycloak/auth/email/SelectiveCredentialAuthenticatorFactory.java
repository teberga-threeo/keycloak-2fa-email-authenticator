package com.mesutpiskin.keycloak.auth.email;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;

import java.util.ArrayList;
import java.util.List;

public class SelectiveCredentialAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "selective-credential-authenticator";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty expected = new ProviderConfigProperty();
        expected.setName("expectedValue");
        expected.setLabel("Expected selectedCredential value");
        expected.setType(ProviderConfigProperty.STRING_TYPE);
        expected.setHelpText("Valor esperado de 'selectedCredential' para ativar este fluxo.");

        configProperties.add(expected);
    }

    @Override public String getId() { return ID; }
    @Override public Authenticator create(KeycloakSession session) { return new SelectiveCredentialAuthenticator(); }
    @Override public String getDisplayType() { return "Selective Credential Condition"; }
    @Override public String getHelpText() { return "Executa o fluxo apenas se 'selectedCredential' for igual ao valor configurado."; }
    @Override public boolean isConfigurable() { return true; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return configProperties; }
    @Override public void init(org.keycloak.Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public Requirement[] getRequirementChoices() {
        return new Requirement[]{Requirement.REQUIRED, Requirement.ALTERNATIVE};
    }
}
