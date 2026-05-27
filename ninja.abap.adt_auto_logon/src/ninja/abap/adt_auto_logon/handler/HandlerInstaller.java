package ninja.abap.adt_auto_logon.handler;

import java.lang.reflect.Field;
import java.util.Map;

import org.eclipse.core.runtime.Platform;
import org.eclipse.ui.IStartup;
import org.osgi.framework.Bundle;

import com.sap.adt.destinations.logon.IAdtLogonService;
import com.sap.adt.destinations.ui.http.authentication.IHttpAuthenticationHandlerUi;

import ninja.abap.adt_auto_logon.Activator;

/**
 * Early startup hook that captures the original SAP auth handler for fallback
 * delegation, then ensures our {@link HeadlessAuthHandlerUi} wins the
 * factory cache race.
 *
 * Uses the ADT bundle's classloader to access the internal factory class,
 * since OSGi does not export internal packages to other bundles.
 */
public class HandlerInstaller implements IStartup {

    private static final String[] AUTH_KINDS = {
            "com.sap.adt.http.authentication.kind.oAuth",
            "com.sap.adt.http.authentication.kind.samlAndReentranceTicket",
            "basicAuth"
    };

    @Override
    public void earlyStartup() {
        try {
            installUiHandler();
            Activator.info("[AutoLogon] UI handler installation complete");
        } catch (Exception e) {
            Activator.error("[AutoLogon] UI handler installation failed — "
                    + "plugin relies on extension point registration only", e);
        }

        try {
            installLogonServiceWrapper();
            Activator.info("[AutoLogon] Logon service wrapper installation complete");
        } catch (Exception e) {
            Activator.error("[AutoLogon] Logon service wrapper installation failed", e);
        }

        new AutoLogonJob().scheduleAfterStartup();
    }

    @SuppressWarnings("unchecked")
    private void installUiHandler() throws Exception {
        Bundle adtUiBundle = Platform.getBundle("com.sap.adt.destinations.ui");
        if (adtUiBundle == null) {
            Activator.warn("[AutoLogon] com.sap.adt.destinations.ui bundle not found — skipping handler installation");
            return;
        }

        Class<?> factoryClass = adtUiBundle.loadClass(
                "com.sap.adt.destinations.ui.http.internal.authentication.HttpAuthenticationHandlerFactoryUi");

        Object factory = factoryClass.getMethod("getInstance").invoke(null);

        Field cacheField = factoryClass.getDeclaredField("cache");
        cacheField.setAccessible(true);
        Map<String, IHttpAuthenticationHandlerUi> cache =
                (Map<String, IHttpAuthenticationHandlerUi>) cacheField.get(factory);

        HeadlessAuthHandlerUi ourHandler = new HeadlessAuthHandlerUi();

        for (String authKind : AUTH_KINDS) {
            IHttpAuthenticationHandlerUi existing = cache.get(authKind);

            if (existing != null && !(existing instanceof HeadlessAuthHandlerUi)) {
                HeadlessAuthHandlerUi.originalHandlers.put(authKind, existing);
                Activator.debug("[AutoLogon] Captured original handler: "
                        + existing.getClass().getName() + " for " + authKind);
            }

            cache.put(authKind, ourHandler);
            Activator.debug("[AutoLogon] Installed handler for " + authKind);
        }
    }

    /**
     * Wraps the ADT logon service singleton with {@link AutoLogonService} so that
     * on-premise logon calls with a null auth token get stored credentials injected.
     * This intercepts the {@code logOnInternalDestDataComplete} path that bypasses
     * the HTTP auth handler mechanism.
     */
    private void installLogonServiceWrapper() throws Exception {
        Bundle destBundle = Platform.getBundle("com.sap.adt.destinations");
        if (destBundle == null) {
            Activator.warn("[AutoLogon] com.sap.adt.destinations bundle not found — skipping logon service wrapper");
            return;
        }

        Class<?> factoryClass = destBundle.loadClass(
                "com.sap.adt.destinations.logon.AdtLogonServiceFactory");

        Field instanceField = factoryClass.getDeclaredField("instance");
        instanceField.setAccessible(true);

        IAdtLogonService realService = (IAdtLogonService) instanceField.get(null);
        if (realService == null) {
            // Force initialization by calling the factory method
            Object created = factoryClass.getMethod("createLogonService").invoke(null);
            realService = (IAdtLogonService) created;
            // Re-read in case createLogonService set the field
            IAdtLogonService fromField = (IAdtLogonService) instanceField.get(null);
            if (fromField != null) {
                realService = fromField;
            }
        }

        if (realService instanceof AutoLogonService) {
            Activator.debug("[AutoLogon] Logon service wrapper already installed");
            return;
        }

        AutoLogonService wrapper = new AutoLogonService(realService);
        instanceField.set(null, wrapper);

        Activator.info("[AutoLogon] Replaced logon service "
                + realService.getClass().getName() + " with AutoLogonService wrapper");
    }
}
