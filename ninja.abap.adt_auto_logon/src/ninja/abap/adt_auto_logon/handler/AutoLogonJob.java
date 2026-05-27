package ninja.abap.adt_auto_logon.handler;

import org.eclipse.core.resources.IProject;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.NullProgressMonitor;
import org.eclipse.core.runtime.Status;
import org.eclipse.core.runtime.jobs.Job;
import org.eclipse.jface.operation.IRunnableContext;

import com.sap.adt.destinations.IDestinationDataProvider;
import com.sap.adt.destinations.logon.AdtLogonServiceFactory;
import com.sap.adt.destinations.logon.IAdtLogonService;
import com.sap.adt.destinations.model.AdtDestinationDataFactory;
import com.sap.adt.destinations.model.IAuthenticationToken;
import com.sap.adt.destinations.model.IDestinationData;
import com.sap.adt.destinations.model.IDestinationDataWritable;
import com.sap.adt.destinations.ui.logon.AdtLogonServiceUIFactory;
import com.sap.adt.destinations.ui.logon.IAdtLogonServiceUI;

import ninja.abap.adt_auto_logon.Activator;
import ninja.abap.adt_auto_logon.preferences.CredencialStore;

/**
 * Background job that authenticates all ABAP projects with stored credentials
 * at Eclipse startup, so sessions are ready before the user interacts.
 *
 * Supports both on-premise (basic auth via IAdtLogonService) and cloud
 * (browser-based auth via the headless IAS handler) systems.
 */
public final class AutoLogonJob extends Job {

    private static final String ABAP_NATURE = "com.sap.adt.abapnature";
    private static final long STARTUP_DELAY_MS = 10_000;

    public AutoLogonJob() {
        super("[AutoLogon] Auto-login at startup");
        setSystem(true);
        setPriority(Job.LONG);
    }

    public void scheduleAfterStartup() {
        schedule(STARTUP_DELAY_MS);
    }

    @Override
    protected IStatus run(IProgressMonitor monitor) {
        IProject[] projects = ResourcesPlugin.getWorkspace().getRoot().getProjects();

        for (IProject project : projects) {
            if (monitor.isCanceled()) break;
            if (!project.isOpen()) continue;

            try {
                if (!project.hasNature(ABAP_NATURE)) continue;
            } catch (CoreException e) {
                continue;
            }

            String destId = project.getName();
            if (!CredencialStore.hasCredentials(destId)) continue;

            loginProject(project, destId);
        }

        return Status.OK_STATUS;
    }

    private void loginProject(IProject project, String destId) {
        Activator.info("[AutoLogon] Auto-login for " + destId);

        // Try direct logon first (works for on-premise basic auth).
        // Falls back to the UI logon service (works for cloud via headless handler).
        if (tryDirectLogon(project, destId)) return;
        tryBrowserBasedLogon(project, destId);
    }

    /**
     * On-premise: authenticate directly via the non-UI logon service
     * with an auth token carrying the stored password.
     */
    private boolean tryDirectLogon(IProject project, String destId) {
        try {
            IAdtLogonService logonService = AdtLogonServiceFactory.createLogonService();
            if (logonService.isLoggedOn(destId)) {
                Activator.info("[AutoLogon] Already logged on: " + destId);
                SessionKeepAlive.start(destId);
                return true;
            }

            IDestinationDataProvider provider =
                    project.getAdapter(IDestinationDataProvider.class);
            if (provider == null) return false;

            IDestinationData destData = provider.getDestinationData();
            if (destData == null) return false;

            IDestinationDataWritable writable = destData.getWritable();
            writable.setPassword(CredencialStore.getPassword(destId));
            IAuthenticationToken authToken =
                    AdtDestinationDataFactory.createAuthenticationToken(writable);

            IStatus status = logonService.ensureLoggedOn(
                    destData, authToken, new NullProgressMonitor());

            if (status.isOK()) {
                Activator.info("[AutoLogon] Auto-login succeeded for " + destId);
                SessionKeepAlive.start(destId);
                return true;
            }

            Activator.debug("[AutoLogon] Direct logon returned "
                    + status.getSeverity() + " for " + destId
                    + ": " + status.getMessage());
            return false;
        } catch (Exception e) {
            Activator.debug("[AutoLogon] Direct logon failed for " + destId
                    + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Cloud: authenticate via the UI logon service, which routes through
     * our headless IAS handler for browser-based auth kinds.
     */
    private void tryBrowserBasedLogon(IProject project, String destId) {
        HeadlessAuthHandlerUi.backgroundMode.set(true);
        try {
            IAdtLogonServiceUI logonService =
                    AdtLogonServiceUIFactory.createLogonServiceUI();

            IRunnableContext bgContext = (fork, cancelable, runnable) ->
                    runnable.run(new NullProgressMonitor());

            IStatus status = logonService.ensureLoggedOn(project, bgContext);
            if (status.isOK()) {
                Activator.info("[AutoLogon] Auto-login succeeded for " + destId);
            } else {
                Activator.warn("[AutoLogon] Auto-login returned "
                        + status.getSeverity() + " for " + destId
                        + ": " + status.getMessage());
            }
        } catch (Exception e) {
            Activator.warn("[AutoLogon] Auto-login failed for " + destId
                    + ": " + e.getMessage());
        } finally {
            HeadlessAuthHandlerUi.backgroundMode.set(false);
        }
    }
}
