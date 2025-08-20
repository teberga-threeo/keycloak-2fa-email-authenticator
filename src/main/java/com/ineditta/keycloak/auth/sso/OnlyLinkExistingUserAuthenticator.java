package com.ineditta.keycloak.auth.sso;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import java.io.IOException;
import java.util.List;

public class OnlyLinkExistingUserAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(OnlyLinkExistingUserAuthenticator.class);

    // Chave usada pelos autenticadores de broker do KC para sinalizar "usuário existente"
    // (mesmo nome usado internamente pelo KC).
    private static final String EXISTING_USER_INFO = "EXISTING_USER_INFO";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserProvider users = session.users();

        // Recupera o BrokeredIdentityContext da sessão (KC 26.x)
        SerializedBrokeredIdentityContext serializedCtx =
                SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                        authSession,
                        AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE
                );

        BrokeredIdentityContext brokerCtx = serializedCtx.deserialize(session, authSession);

        if (brokerCtx == null) {
            LOG.warn("BrokeredIdentityContext is null in first-broker-login");
            context.failure(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR);
            return;
        }

        String email = trimOrNull(brokerCtx.getEmail());
        String username = trimOrNull(brokerCtx.getUsername());

        UserModel match = null;

        // 1) Match por EMAIL (preferencial)
        if (email != null) {
            UserModel byEmail = users.getUserByEmail(realm, email);
            if (byEmail != null) {
                match = byEmail;
            } else {
                // fallback (alguns stores podem não indexar getUserByEmail):
                List<UserModel> list = users.searchForUserByUserAttributeStream(realm, "email", email).toList();
                if (list.size() == 1) {
                    match = list.get(0);
                } else if (list.size() > 1) {
                    LOG.warnf("Multiple users found with same email: %s", email);
                    context.failure(AuthenticationFlowError.USER_CONFLICT);
                    return;
                }
            }
        }

        // 2) Se não achou por email, tenta USERNAME
        if (match == null && username != null) {
            UserModel byUsername = users.getUserByUsername(realm, username);
            if (byUsername != null) match = byUsername;
        }

        // 3) Decide
        if (match == null) {
            LOG.warnf("No local user found for IdP user (email=%s, username=%s). Failing without creation.", email, username);
            context.failure(AuthenticationFlowError.INVALID_USER);
            return;
        }

        if (!match.isEnabled()) {
            LOG.warnf("Matched user is DISABLED: %s", match.getUsername());
            context.failure(AuthenticationFlowError.USER_DISABLED);
            return;
        }

        // 4) Sinaliza ao subfluxo "Handle/Confirm Existing Account" que há usuário existente
        try {
            ExistingUserInfo info = new ExistingUserInfo(match.getId(), match.getUsername(), match.getEmail());
            String json = JsonSerialization.writeValueAsString(info);
            authSession.setAuthNote(EXISTING_USER_INFO, json);
        } catch (IOException e) {
            LOG.error("Failed to serialize ExistingUserInfo", e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        // Define o usuário no contexto e segue o fluxo (subflows farão a vinculação)
        context.setUser(match);
        context.success();
    }

    @Override public void action(AuthenticationFlowContext context) { /* not interactive */ }
    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
    @Override public void close() { }

    private static String trimOrNull(String v) {
        return (v == null || v.isBlank()) ? null : v.trim();
    }

    // POJO simples armazenado em JSON na note EXISTING_USER_INFO
    public static class ExistingUserInfo {
        public String id;
        public String username;
        public String email;
        public ExistingUserInfo() {}
        public ExistingUserInfo(String id, String username, String email) {
            this.id = id; this.username = username; this.email = email;
        }
    }
}
