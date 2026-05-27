package ninja.abap.adt_auto_logon.handler;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;

import com.sap.adt.destinations.logon.IAdtLogonService;
import com.sap.adt.destinations.model.AdtDestinationDataFactory;
import com.sap.adt.destinations.model.IAuthenticationToken;
import com.sap.adt.destinations.model.IDestinationData;
import com.sap.adt.destinations.model.IDestinationDataWritable;

import ninja.abap.adt_auto_logon.Activator;
import ninja.abap.adt_auto_logon.preferences.CredencialStore;

/**
 * Wraps the real {@link IAdtLogonService} to auto-fill stored credentials
 * when {@code ensureLoggedOn} is called with a null auth token.
 *
 * This intercepts the on-premise logon path where {@code LogonServiceUI$4}
 * calls {@code logonService.ensureLoggedOn(destData, null, monitor)} —
 * normally this triggers the password dialog. With this wrapper, stored
 * credentials are injected automatically.
 */
public final class AutoLogonService implements IAdtLogonService {

    private final IAdtLogonService delegate;

    public AutoLogonService(IAdtLogonService delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean isLoggedOn(String destinationName) {
        return delegate.isLoggedOn(destinationName);
    }

    @Override
    public IStatus ensureLoggedOn(IDestinationData destinationData,
                                   IAuthenticationToken authToken,
                                   IProgressMonitor monitor) {
        if (authToken == null && destinationData != null) {
            String destId = destinationData.getId();
            if (destId != null && CredencialStore.hasCredentials(destId)) {
                Activator.debug("[AutoLogon] Injecting stored credentials for " + destId);
                try {
                    IDestinationDataWritable writable = destinationData.getWritable();
                    writable.setPassword(CredencialStore.getPassword(destId));
                    authToken = AdtDestinationDataFactory.createAuthenticationToken(writable);
                    IStatus status = delegate.ensureLoggedOn(destinationData, authToken, monitor);
                    if (status.isOK()) {
                        Activator.info("[AutoLogon] Auto-logon succeeded for " + destId);
                        SessionKeepAlive.start(destId);
                        return status;
                    }
                    Activator.debug("[AutoLogon] Auto-logon returned "
                            + status.getSeverity() + " for " + destId
                            + ": " + status.getMessage());
                } catch (Exception e) {
                    Activator.debug("[AutoLogon] Auto-logon failed for " + destId
                            + ": " + e.getMessage());
                }
            }
        }
        return delegate.ensureLoggedOn(destinationData, authToken, monitor);
    }
}
