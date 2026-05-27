package ninja.abap.adt_auto_logon.ias;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.eclipse.jface.dialogs.InputDialog;
import org.eclipse.jface.window.Window;
import org.eclipse.swt.widgets.Display;

import ninja.abap.adt_auto_logon.Activator;

/**
 * Headless browser that drives the IAS login flow for both OAuth and
 * SAML+Reentrance-Ticket authentication kinds.
 *
 * Takes a start URL (the same URL ADT would open in a real browser),
 * navigates through IAS login, and follows the final redirect to the
 * local Jetty server that the ADT facade started.
 *
 * The Jetty server captures the token/code, and the facade completes
 * the logon.
 */
public final class IasFlowExecutor {

    private static final int MAX_STEPS = 20;
    private static final Duration TIMEOUT = Duration.ofSeconds(30);

    private final HttpClient http;
    private final CookieJar jar = new CookieJar();

    public IasFlowExecutor() {
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /**
     * Execute the headless IAS login flow.
     *
     * @param startUrl    the OAuth authorize or SAML reentrance-ticket URL
     * @param username    IAS username (email)
     * @param password    IAS password
     * @param display     SWT display for 2FA dialog (may be null in headless tests)
     * @throws IasFlowException on auth failure
     */
    public void execute(URI startUrl, String username, String password, Display display)
            throws IasFlowException {
        Activator.debug("[IAS] Starting headless flow: " + startUrl.getHost());

        URI currentUri = startUrl;
        String body = null;
        int statusCode = 0;
        boolean credentialsSubmitted = false;

        for (int step = 0; step < MAX_STEPS; step++) {
            HttpResponse<String> resp;
            if (body == null) {
                resp = get(currentUri);
            } else {
                resp = post(currentUri, body);
                body = null;
            }

            statusCode = resp.statusCode();
            jar.store(currentUri.getHost(), resp);

            // Redirect — follow it, but check if it targets localhost (token callback)
            if (statusCode >= 300 && statusCode < 400) {
                String location = resp.headers().firstValue("location").orElse(null);
                if (location == null) {
                    throw new IasFlowException("Redirect without Location header at step " + step);
                }
                URI next = resolve(location, currentUri);

                if (isLocalhostCallback(next)) {
                    deliverToJetty(next);
                    return;
                }
                currentUri = next;
                continue;
            }

            if (statusCode != 200) {
                throw new IasFlowException("Unexpected HTTP " + statusCode + " at " + currentUri);
            }

            String html = resp.body();
            if (html == null) html = "";

            // Login form — submit credentials (checked before SAML because
            // the IAS login page carries SAMLRequest as a hidden field)
            if (HtmlParser.isLoginForm(html) && !credentialsSubmitted) {
                String form = HtmlParser.firstForm(html);
                if (form == null) throw new IasFlowException("Login form detected but not parseable");
                String action = HtmlParser.attribute(form, "action");
                if (action == null) throw new IasFlowException("Login form has no action");

                Map<String, String> fields = HtmlParser.hiddenFields(form);
                fields.put("j_username", username);
                fields.put("j_password", password);

                currentUri = resolve(action, currentUri);
                body = encodeForm(fields);
                credentialsSubmitted = true;
                Activator.debug("[IAS] Submitting credentials to " + currentUri.getHost());
                continue;
            }

            // Login form shown again after credentials — bad password
            if (HtmlParser.isLoginForm(html) && credentialsSubmitted) {
                throw new IasFlowException(
                        "Authentication failed: IAS returned the login form again. Check username/password.");
            }

            // 2FA challenge (checked before SAML auto-submit)
            if (HtmlParser.isTwoFaChallenge(html)) {
                String otp = promptForOtp(display);
                if (otp == null) throw new IasFlowException("2FA cancelled by user");

                String form = HtmlParser.firstForm(html);
                if (form == null) throw new IasFlowException("2FA form not parseable");
                String action = HtmlParser.attribute(form, "action");
                if (action == null) throw new IasFlowException("2FA form has no action");

                Map<String, String> fields = HtmlParser.hiddenFields(form);
                String existingUser = HtmlParser.inputValue(form, "j_username");
                fields.put("j_username", existingUser != null ? existingUser : username);
                fields.put("j_otpcode", otp.trim());

                currentUri = resolve(action, currentUri);
                body = encodeForm(fields);
                Activator.debug("[IAS] Submitting OTP");
                continue;
            }

            // Unsupported challenge (WebAuthn, push)
            if (HtmlParser.isUnsupportedChallenge(html)) {
                throw new IasFlowException(
                        "IAS requires WebAuthn or push notification — not supported. "
                        + "Configure a TOTP policy or use a service user.");
            }

            // Auto-submit SAML form (SAMLRequest or SAMLResponse)
            if (HtmlParser.isSamlAutoSubmit(html)) {
                String form = HtmlParser.firstForm(html);
                if (form == null) throw new IasFlowException("SAML form detected but not parseable");
                String action = HtmlParser.attribute(form, "action");
                if (action == null) throw new IasFlowException("SAML form has no action");
                currentUri = resolve(action, currentUri);
                body = encodeForm(HtmlParser.hiddenFields(form));
                Activator.debug("[IAS] Auto-submitting SAML form to " + currentUri.getHost());
                continue;
            }

            throw new IasFlowException("Unrecognized IAS page at " + currentUri
                    + ". Excerpt: " + html.substring(0, Math.min(200, html.length())));
        }

        throw new IasFlowException("IAS flow did not complete within " + MAX_STEPS + " steps");
    }

    // --- HTTP helpers ---

    private HttpResponse<String> get(URI uri) throws IasFlowException {
        try {
            HttpRequest req = HttpRequest.newBuilder(uri)
                    .GET()
                    .timeout(TIMEOUT)
                    .header("Cookie", jar.get(uri.getHost()))
                    .header("User-Agent", "Eclipse/ADT")
                    .build();
            return http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IasFlowException("GET " + uri + " failed: " + e.getMessage(), e);
        }
    }

    private HttpResponse<String> post(URI uri, String formBody) throws IasFlowException {
        try {
            HttpRequest req = HttpRequest.newBuilder(uri)
                    .POST(HttpRequest.BodyPublishers.ofString(formBody))
                    .timeout(TIMEOUT)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Cookie", jar.get(uri.getHost()))
                    .header("User-Agent", "Eclipse/ADT")
                    .build();
            return http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IasFlowException("POST " + uri + " failed: " + e.getMessage(), e);
        }
    }

    /** Follow the final redirect to localhost — delivers the token to ADT's Jetty server. */
    private void deliverToJetty(URI localhostUri) throws IasFlowException {
        Activator.debug("[IAS] Delivering token to local callback: " + localhostUri);
        try {
            HttpRequest req = HttpRequest.newBuilder(localhostUri)
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 400) {
                Activator.warn("[IAS] Jetty callback returned HTTP " + resp.statusCode());
            }
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IasFlowException("Failed to deliver token to local server: " + e.getMessage(), e);
        }
    }

    // --- Utility ---

    private static boolean isLocalhostCallback(URI uri) {
        String host = uri.getHost();
        return host != null
                && (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]"));
    }

    private static URI resolve(String location, URI base) {
        if (location.startsWith("http://") || location.startsWith("https://")) {
            return URI.create(location);
        }
        return base.resolve(location);
    }

    private static String encodeForm(Map<String, String> fields) {
        return fields.entrySet().stream()
                .map(e -> enc(e.getKey()) + "=" + enc(e.getValue()))
                .collect(Collectors.joining("&"));
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** Prompt for TOTP code on the UI thread. Returns null if cancelled. */
    private static String promptForOtp(Display display) {
        if (display == null || display.isDisposed()) return null;

        AtomicReference<String> result = new AtomicReference<>();
        display.syncExec(() -> {
            InputDialog dlg = new InputDialog(
                    display.getActiveShell(),
                    "Two-Factor Authentication",
                    "Your identity provider requires a verification code.\n"
                            + "Enter the code from your authenticator app:",
                    "",
                    input -> {
                        if (input == null || input.trim().isEmpty()) return "Code required";
                        if (!input.trim().matches("\\d{4,8}")) return "Enter a 4-8 digit code";
                        return null;
                    });
            if (dlg.open() == Window.OK) {
                result.set(dlg.getValue());
            }
        });
        return result.get();
    }

    public static final class IasFlowException extends Exception {
        private static final long serialVersionUID = 1L;

        public IasFlowException(String message) { super(message); }
        public IasFlowException(String message, Throwable cause) { super(message, cause); }
    }
}
