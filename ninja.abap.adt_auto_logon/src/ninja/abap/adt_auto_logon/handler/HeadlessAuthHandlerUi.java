package ninja.abap.adt_auto_logon.handler;

import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IConfigurationElement;
import org.eclipse.core.runtime.IExtensionPoint;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Platform;
import org.eclipse.core.runtime.Status;
import org.eclipse.jface.operation.IRunnableContext;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.osgi.framework.Bundle;

import com.sap.adt.destinations.http.systemurlinfo.AdtSystemUrlInfoProviderFactory;
import com.sap.adt.destinations.http.systemurlinfo.ISystemUrlInfo;
import com.sap.adt.destinations.http.systemurlinfo.ISystemUrlInfoProvider;
import com.sap.adt.destinations.logon.http.AdtHttpLogonHandlingFactory;
import com.sap.adt.destinations.logon.http.browserbased.IAdtHttpBrowserBasedLogonHandlingFacade;
import com.sap.adt.destinations.model.http.internal.api.IHttpDestinationData;
import com.sap.adt.destinations.ui.http.authentication.HttpLogonUiHelperFactory;
import com.sap.adt.destinations.ui.http.authentication.IHttpAuthenticationHandlerUi;
import com.sap.adt.destinations.ui.http.authentication.IHttpLogonUiHelper;

import ninja.abap.adt_auto_logon.Activator;
import ninja.abap.adt_auto_logon.preferences.CredencialStore;
import ninja.abap.adt_auto_logon.ias.IasFlowExecutor;
import ninja.abap.adt_auto_logon.ias.IasFlowExecutor.IasFlowException;

/**
 * Replaces the browser-based logon wizard with headless IAS authentication.
 *
 * Registered via the {@code com.sap.adt.destinations.ui.httpAuthenticationHandlerUi}
 * extension point for both OAuth and SAML+Reentrance-Ticket authentication kinds.
 *
 * When stored credentials exist for a project, this handler:
 * 1. Creates the standard ADT logon facade (which starts a local Jetty server)
 * 2. Runs the IAS login flow headlessly in a background thread
 * 3. The headless flow delivers the token to Jetty via HTTP
 * 4. The facade completes the logon (token exchange, session establishment)
 *
 * When no credentials are stored, delegates to the original browser-based handler.
 */
public class HeadlessAuthHandlerUi implements IHttpAuthenticationHandlerUi {

    /**
     * Original SAP handlers per auth kind, captured by {@link HandlerInstaller}.
     * Used as fallback when no credentials are configured.
     */
    static final ConcurrentHashMap<String, IHttpAuthenticationHandlerUi> originalHandlers =
            new ConcurrentHashMap<>();

    /** Set by {@link AutoLogonJob} to suppress browser fallback during background logon. */
    static final ThreadLocal<Boolean> backgroundMode = ThreadLocal.withInitial(() -> Boolean.FALSE);

    @Override
    public IStatus handleLogon(IHttpDestinationData destinationData,
                                Properties domainSpecificVolatileProperties,
                                Shell shell,
                                IRunnableContext runnableContext) {

        String destId = destinationData.getId();

        if (!CredencialStore.hasCredentials(destId)) {
            Activator.debug("[AutoLogon] No credentials for " + destId + " — delegating to original handler");
            return delegateToOriginal(destinationData, domainSpecificVolatileProperties, shell, runnableContext);
        }

        String authKind = destinationData.getHttpSystemConfiguration().getAuthenticationKind();
        if ("basicAuth".equals(authKind)) {
            return handleBasicAuthLogon(destinationData, domainSpecificVolatileProperties,
                    shell, runnableContext);
        }

        return handleCloudLogon(destinationData, domainSpecificVolatileProperties,
                shell, runnableContext);
    }

    private IStatus handleBasicAuthLogon(IHttpDestinationData destinationData,
                                          Properties volatileProps,
                                          Shell shell,
                                          IRunnableContext runnableContext) {
        String destId = destinationData.getId();
        String password = CredencialStore.getPassword(destId);

        Activator.info("[AutoLogon] Basic auth logon for " + destId);

        volatileProps.put("password", password);
        try {
            IHttpLogonUiHelper helper =
                    HttpLogonUiHelperFactory.createHttpLogonUiHelper(destinationData, runnableContext);
            IStatus status = helper.tryToConnect(volatileProps);

            if (status.isOK()) {
                Activator.info("[AutoLogon] Basic auth logon succeeded for " + destId);
                SessionKeepAlive.start(destId);
                return status;
            }

            Activator.warn("[AutoLogon] Basic auth logon failed for " + destId
                    + ": " + status.getMessage());
        } catch (Exception e) {
            Activator.warn("[AutoLogon] Basic auth logon error for " + destId
                    + ": " + e.getMessage());
        } finally {
            volatileProps.remove("password");
        }

        if (backgroundMode.get()) {
            Activator.warn("[AutoLogon] Skipping dialog fallback (background mode)");
            return Status.error("Basic auth logon failed for " + destId);
        }

        Activator.warn("[AutoLogon] Falling back to password dialog");
        return delegateToOriginal(destinationData, volatileProps, shell, runnableContext);
    }

    private IStatus handleCloudLogon(IHttpDestinationData destinationData,
                                      Properties domainSpecificVolatileProperties,
                                      Shell shell,
                                      IRunnableContext runnableContext) {

        String destId = destinationData.getId();
        String username = CredencialStore.getUsername(destId);
        String password = CredencialStore.getPassword(destId);
        Display display = shell != null ? shell.getDisplay() : Display.getDefault();

        Activator.info("[AutoLogon] Headless logon for " + destId);

        final IStatus[] result = { Status.CANCEL_STATUS };

        try {
            runnableContext.run(true, true, monitor -> {
                result[0] = performHeadlessLogon(
                        destinationData, domainSpecificVolatileProperties,
                        username, password, display, monitor);
            });
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            Activator.error("[AutoLogon] Headless logon failed", cause);
            result[0] = Status.error("Headless logon failed: " + cause.getMessage(), cause);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            result[0] = Status.CANCEL_STATUS;
        }

        if (!result[0].isOK() && result[0] != Status.CANCEL_STATUS) {
            if (backgroundMode.get()) {
                Activator.warn("[AutoLogon] Headless logon failed in background mode — skipping browser fallback");
                return result[0];
            }
            Activator.warn("[AutoLogon] Headless logon failed — falling back to browser flow");
            return delegateToOriginal(destinationData, domainSpecificVolatileProperties, shell, runnableContext);
        }

        return result[0];
    }

    private IStatus performHeadlessLogon(IHttpDestinationData destinationData,
                                          Properties volatileProps,
                                          String username, String password,
                                          Display display,
                                          IProgressMonitor monitor) {

        monitor.beginTask("Authenticating...", IProgressMonitor.UNKNOWN);

        String destId = destinationData.getId();
        Activator.debug("[AutoLogon] Volatile props at entry: " + volatileProps.size() + " entries");

        ensureHttpDestinationRegistered(destId, destinationData, volatileProps);

        IAdtHttpBrowserBasedLogonHandlingFacade facade =
                AdtHttpLogonHandlingFactory.createBrowserBasedLogonHandlingFacade(
                        destinationData, volatileProps);
        try {
            // 1. Fetch OAuth/SAML endpoint info from the system
            monitor.subTask("Fetching system information...");
            String systemUrl = destinationData.getHttpSystemConfiguration().getSystemUrl().toString();
            ISystemUrlInfoProvider urlInfoProvider =
                    AdtSystemUrlInfoProviderFactory.createProviderForExistingDestination(destinationData);
            ISystemUrlInfo urlInfo;
            try {
                urlInfo = urlInfoProvider.getSystemUrlInfo(systemUrl, monitor);
            } catch (CoreException e) {
                return Status.error("Failed to fetch system URL info: " + e.getMessage(), e);
            }
            if (monitor.isCanceled()) return Status.CANCEL_STATUS;

            facade.setAbapSystemUrlInfo(urlInfo);

            // 2. Begin logon (starts Jetty, returns the URL to open in browser)
            URI browserUrl = facade.beginBrowserBasedLogon();
            Activator.debug("[AutoLogon] Browser URL: " + browserUrl);

            // 3. Drive the IAS flow headlessly in a parallel thread.
            //    The flow ends by GETting the localhost callback URL,
            //    which feeds the token to the Jetty server the facade started.
            monitor.subTask("Authenticating with identity provider...");
            CompletableFuture<Void> headless = CompletableFuture.runAsync(() -> {
                try {
                    new IasFlowExecutor().execute(browserUrl, username, password, display);
                } catch (IasFlowException e) {
                    throw new RuntimeException(e);
                }
            });

            // 4. The facade blocks until Jetty receives the token, then
            //    exchanges it for a session and returns.
            monitor.subTask("Establishing session...");
            IStatus status = facade.awaitTokenAndLogOn(monitor, preflightData -> Status.OK_STATUS);
            Activator.debug("[AutoLogon] awaitTokenAndLogOn returned: " + status.getSeverity()
                    + " (" + status.getMessage() + ")");

            // 5. Check the headless future for errors
            try {
                headless.get(1, TimeUnit.SECONDS);
            } catch (Exception e) {
                if (status.isOK()) {
                    Activator.warn("[AutoLogon] Headless future errored but facade succeeded: " + e.getMessage());
                }
            }

            Activator.debug("[AutoLogon] Volatile props after logon: " + volatileProps.size() + " entries");

            // The facade authenticated via its own HTTP connection, but the shared
            // HttpSystemConnection (used by all subsequent requests) still has
            // isLoggedOn()==false. Send a LOGON-mode request through the shared
            // connection so that it picks up the session cookies from the volatile
            // properties and sets isLoggedOn(true).
            if (status.isOK()) {
                initializeSharedConnection(destId, monitor);
                SessionKeepAlive.start(destId);
            }

            return status;

        } finally {
            facade.dispose();
            monitor.done();
        }
    }

    /**
     * Sends a LOGON-mode request through the shared HttpSystemConnection so that
     * it becomes initialized (isLoggedOn=true, CSRF token, session cookies, etc.).
     * Without this, the first real request after handleLogon returns would fail
     * with NotLoggedOnAnymoreException because the shared connection was never used
     * for the facade's logon — the facade uses its own internal HTTP connection.
     */
    private void initializeSharedConnection(String destId, IProgressMonitor monitor) {
        try {
            Bundle commBundle = Platform.getBundle("com.sap.adt.communication");
            if (commBundle == null) return;

            Class<?> connFactoryClass = commBundle.loadClass(
                    "com.sap.adt.communication.http.systemconnection.HttpSystemConnectionFactory");
            Object factory = connFactoryClass.getMethod("getInstance").invoke(null);
            Object sysConn = connFactoryClass
                    .getMethod("getOrCreateHttpSystemConnection", String.class)
                    .invoke(factory, destId);

            sysConn.getClass()
                    .getMethod("initializeAndCheckCompatibility", IProgressMonitor.class)
                    .invoke(sysConn, monitor);

            Activator.debug("[AutoLogon] Shared system connection initialized for " + destId);
        } catch (Exception e) {
            Activator.warn("[AutoLogon] Could not initialize shared connection: " + e.getMessage());
        }
    }

    /**
     * Ensures the destination is registered in the IHttpDestinationRegistry.
     * LogonServiceUI.showInputDialog calls handleLogon but does NOT register the
     * destination in the HTTP registry. The compatibility check that runs after
     * handleLogon returns needs the destination to be registered there.
     */
    private void ensureHttpDestinationRegistered(String destId,
                                                  IHttpDestinationData destinationData,
                                                  Properties volatileProps) {
        try {
            Bundle commBundle = Platform.getBundle("com.sap.adt.communication");
            if (commBundle == null) return;

            Class<?> factoryClass = commBundle.loadClass(
                    "com.sap.adt.communication.http.internal.api.HttpDestinationRegistryFactory");
            Class<?> registryIface = commBundle.loadClass(
                    "com.sap.adt.communication.http.internal.api.IHttpDestinationRegistry");
            Class<?> destDataIface = commBundle.loadClass(
                    "com.sap.adt.destinations.model.http.internal.api.IHttpDestinationData");

            Object registry = factoryClass.getMethod("getHttpDestinationRegistry").invoke(null);

            boolean registered = (boolean) registryIface
                    .getMethod("isRegistered", String.class)
                    .invoke(registry, destId);

            Activator.debug("[AutoLogon] HTTP destination '" + destId + "' registered: " + registered);

            if (!registered) {
                registryIface
                        .getMethod("register", String.class, destDataIface, Properties.class)
                        .invoke(registry, destId, destinationData, volatileProps);
                Activator.debug("[AutoLogon] Registered destination '" + destId + "' in HTTP registry");
            }
        } catch (Exception e) {
            Activator.warn("[AutoLogon] Could not check/register HTTP destination: " + e.getMessage());
        }
    }

    private IStatus delegateToOriginal(IHttpDestinationData destinationData,
                                        Properties volatileProps,
                                        Shell shell,
                                        IRunnableContext runnableContext) {
        String authKind = destinationData.getHttpSystemConfiguration().getAuthenticationKind();
        IHttpAuthenticationHandlerUi fallback = originalHandlers.get(authKind);
        if (fallback == null) {
            fallback = findSapHandler(authKind);
            if (fallback != null) {
                originalHandlers.put(authKind, fallback);
            }
        }
        if (fallback != null) {
            return fallback.handleLogon(destinationData, volatileProps, shell, runnableContext);
        }
        Activator.warn("[AutoLogon] No original handler available for " + authKind);
        return Status.error("No authentication handler available. "
                + "Configure credentials in project Properties > Auto-Logon.");
    }

    private IHttpAuthenticationHandlerUi findSapHandler(String authKind) {
        try {
            IExtensionPoint ep = Platform.getExtensionRegistry()
                    .getExtensionPoint("com.sap.adt.destinations.ui",
                            "httpAuthenticationHandlerUi");
            if (ep == null) return null;

            for (IConfigurationElement ce : ep.getConfigurationElements()) {
                if (!"handler".equals(ce.getName())) continue;
                String kind = ce.getAttribute("authenticationKind");
                if (!authKind.equals(kind)) continue;

                Object handler = ce.createExecutableExtension("class");
                if (handler instanceof IHttpAuthenticationHandlerUi
                        && !(handler instanceof HeadlessAuthHandlerUi)) {
                    Activator.debug("[AutoLogon] Found SAP handler: "
                            + handler.getClass().getName());
                    return (IHttpAuthenticationHandlerUi) handler;
                }
            }
        } catch (Exception e) {
            Activator.error("[AutoLogon] Failed to look up SAP handler", e);
        }
        return null;
    }
}
