package com.mesutpiskin.keycloak.auth.email;

import jakarta.ws.rs.core.MultivaluedMap;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;

import java.util.Set;

public class Select2faMethodAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        
        SubjectCredentialManager credentialManager = user.credentialManager();

        // Verificar credenciais TOTP
        boolean hasTotp = credentialManager.getStoredCredentialsByTypeStream(OTPCredentialModel.TOTP)
                                          .findAny()
                                          .isPresent();
        
        System.out.println("TOTP Configurado: " + hasTotp);  // Log TOTP

        // Verificar credenciais OTP
        @SuppressWarnings("deprecation")
		boolean hasOtp = credentialManager.getStoredCredentialsByTypeStream(OTPCredentialModel.OTP)
                                          .findAny()
                                          .isPresent();
        
        System.out.println("OTP Configurado: " + hasOtp);  // Log OTP

        // Verificar credenciais HOTP
        boolean hasHotp = credentialManager.getStoredCredentialsByTypeStream(OTPCredentialModel.HOTP)
                                          .findAny()
                                          .isPresent();
        
        System.out.println("HOTP Configurado: " + hasHotp);  // Log HOTP

        boolean isOtpConfigured = hasTotp || hasHotp || hasOtp;

        System.out.println("Algum OTP Configurado: " + isOtpConfigured);  // Log

        Set<String> requiredActions = user.getRequiredActionsStream().collect(java.util.stream.Collectors.toSet());
        
        // Mostra botão App (totp) somente se Required Action para configurar TOTP existir
        boolean showApp = requiredActions.contains(UserModel.RequiredAction.CONFIGURE_TOTP.name()) || isOtpConfigured;

        System.out.println("ShowApp: " + showApp);  // Log showApp
        
        // Email OTP sempre disponível, então não precisa checar

        context.challenge(
                context.form()
                    .setAttribute("showApp", showApp)
                    .createForm("select-2fa-method.ftl")
            );
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String method = formData.getFirst("selectedCredential");

        if (method == null || (!method.equals("otp-email") && !method.equals("totp"))) {
            context.form()
                .setError("invalidCredential")
                .setAttribute("showApp", true)
                .createForm("select-2fa-method.ftl");
            return;
        }

        context.getAuthenticationSession().setAuthNote("selectedCredential", method);
        context.success();
    }

    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(org.keycloak.models.KeycloakSession session,
                                           org.keycloak.models.RealmModel realm,
                                           UserModel user) { return true; }
    @Override public void setRequiredActions(org.keycloak.models.KeycloakSession session,
                                            org.keycloak.models.RealmModel realm,
                                            UserModel user) {}
    @Override public void close() {}
}