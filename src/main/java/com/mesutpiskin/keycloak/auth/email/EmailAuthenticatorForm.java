package com.mesutpiskin.keycloak.auth.email;

import lombok.extern.jbosslog.JBossLog;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.common.util.SecretGenerator;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@JBossLog
public class EmailAuthenticatorForm extends AbstractUsernameFormAuthenticator {
	private static final int MIN_RESEND_INTERVAL_SECONDS = 30;
	private static final String LAST_RESEND_TIMESTAMP = "email-code-last-resend";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        challenge(context, null);
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        generateAndSendEmailCode(context);

        LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
        if (error != null) {
            if (field != null) {
                form.addError(new FormMessage(field, error));
            } else {
                form.setError(error);
            }
        }
        Response response = form.createForm("email-code-form.ftl");
        context.challenge(response);
        return response;
    }

    private void generateAndSendEmailCode(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        AuthenticationSessionModel session = context.getAuthenticationSession();

        // respect minimum time
        String lastResendTimestamp = session.getAuthNote(LAST_RESEND_TIMESTAMP);
        if (lastResendTimestamp != null) {
            long lastSentTime = Long.parseLong(lastResendTimestamp);
            long now = System.currentTimeMillis();
            if ((now - lastSentTime) < (MIN_RESEND_INTERVAL_SECONDS * 1000L)) {
                // minimum time to send
                log.warn("Tentativa de reenvio antes do tempo mínimo.");
                return;
            }
        }

        int length = EmailConstants.DEFAULT_LENGTH;
        int ttl = EmailConstants.DEFAULT_TTL;
        if (config != null) {
            length = Integer.parseInt(config.getConfig().get(EmailConstants.CODE_LENGTH));
            ttl = Integer.parseInt(config.getConfig().get(EmailConstants.CODE_TTL));
        }

        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
        sendEmailWithCode(context.getSession(), context.getRealm(), context.getUser(), code, ttl);

        session.setAuthNote(EmailConstants.CODE, code);
        session.setAuthNote(EmailConstants.CODE_TTL, Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
        // update sent timestamp
        session.setAuthNote(LAST_RESEND_TIMESTAMP, Long.toString(System.currentTimeMillis()));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        UserModel userModel = context.getUser();
        if (!enabledUser(context, userModel)) {
            // error in context is set in enabledUser/isDisabledByBruteForce
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("resend")) {
            String lastResend = context.getAuthenticationSession().getAuthNote(LAST_RESEND_TIMESTAMP);
            if (lastResend != null) {
                long lastSentTime = Long.parseLong(lastResend);
                long now = System.currentTimeMillis();
                long secondsSinceLast = (now - lastSentTime) / 1000;
                long secondsRemaining = MIN_RESEND_INTERVAL_SECONDS - secondsSinceLast;

                if (secondsRemaining > 0) {
                    String msg = String.format("Por favor, aguarde %d segundo%s antes de reenviar o código.",
                            secondsRemaining,
                            secondsRemaining > 1 ? "s" : "");
                    Response challengeResponse = challenge(context, msg, EmailConstants.CODE);
                    context.challenge(challengeResponse);
                    return;
                }
            }

            // Resend allowed
            generateAndSendEmailCode(context);
            showCleanForm(context);
            return;
        }


        if (formData.containsKey("cancel")) {
            resetEmailCode(context);
            context.resetFlow();
            return;
        }

        AuthenticationSessionModel session = context.getAuthenticationSession();
        String code = session.getAuthNote(EmailConstants.CODE);
        String ttl = session.getAuthNote(EmailConstants.CODE_TTL);
        String enteredCode = formData.getFirst(EmailConstants.CODE);

        if (enteredCode.equals(code)) {
            if (Long.parseLong(ttl) < System.currentTimeMillis()) {
                // expired
                context.getEvent().user(userModel).error(Errors.EXPIRED_CODE);
                Response challengeResponse = challenge(context, Messages.EXPIRED_ACTION_TOKEN_SESSION_EXISTS, EmailConstants.CODE);
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challengeResponse);
            } else {
                // valid
                resetEmailCode(context);
                context.success();
            }
        } else {
            // invalid
            AuthenticationExecutionModel execution = context.getExecution();
            if (execution.isRequired()) {
                context.getEvent().user(userModel).error(Errors.INVALID_USER_CREDENTIALS);
                Response challengeResponse = challenge(context, Messages.INVALID_ACCESS_CODE, EmailConstants.CODE);
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            } else if (execution.isConditional() || execution.isAlternative()) {
                context.attempted();
            }
        }
    }

    protected String disabledByBruteForceError() {
        return Messages.INVALID_ACCESS_CODE;
    }

    private void resetEmailCode(AuthenticationFlowContext context) {
        context.getAuthenticationSession().removeAuthNote(EmailConstants.CODE);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getEmail() != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    private void sendEmailWithCode(KeycloakSession session, RealmModel realm, UserModel user, String code, int ttl) {
        if (user.getEmail() == null) {
            log.warnf("Could not send access code email due to missing email. realm=%s user=%s", realm.getId(), user.getUsername());
            throw new AuthenticationFlowException(AuthenticationFlowError.INVALID_USER);
        }

        Map<String, Object> mailBodyAttributes = new HashMap<>();
        mailBodyAttributes.put("username", user.getUsername());
        mailBodyAttributes.put("code", code);
        mailBodyAttributes.put("ttl", ttl);

        String realmName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
        List<Object> subjectParams = List.of(realmName);
        try {
            EmailTemplateProvider emailProvider = session.getProvider(EmailTemplateProvider.class);
            emailProvider.setRealm(realm);
            emailProvider.setUser(user);
            // Don't forget to add the welcome-email.ftl (html and text) template to your theme.
            emailProvider.send("emailCodeSubject", subjectParams, "code-email.ftl", mailBodyAttributes);
        } catch (EmailException eex) {
            log.errorf(eex, "Failed to send access code email. realm=%s user=%s", realm.getId(), user.getUsername());
        }
    }
    
    private void showCleanForm(AuthenticationFlowContext context) {
        LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
        Response response = form.createForm("email-code-form.ftl");
        context.challenge(response);
    }
}
