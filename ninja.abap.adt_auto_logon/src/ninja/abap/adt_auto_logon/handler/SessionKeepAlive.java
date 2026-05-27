package ninja.abap.adt_auto_logon.handler;

import java.net.URI;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.core.runtime.jobs.Job;

import com.sap.adt.communication.message.AdtRequestFactory;
import com.sap.adt.communication.message.IRequest;
import com.sap.adt.communication.message.IRequestFactory;
import com.sap.adt.communication.session.AdtSystemSessionFactory;
import com.sap.adt.communication.session.IStatelessSystemSession;
import com.sap.adt.communication.session.ISystemSessionFactory;

import ninja.abap.adt_auto_logon.Activator;

/**
 * Sends periodic lightweight requests through each authenticated destination
 * to prevent the server-side session from expiring during idle periods.
 *
 * Started automatically after a successful headless logon. Stops itself when
 * the session is no longer active or when the plugin shuts down.
 */
public final class SessionKeepAlive {

    private static final long INTERVAL_MS = 5 * 60 * 1000;
    private static final URI DISCOVERY_URI = URI.create("/sap/bc/adt/core/discovery");

    private static final ConcurrentHashMap<String, Job> activeJobs = new ConcurrentHashMap<>();

    private SessionKeepAlive() {}

    public static void start(String destId) {
        stop(destId);

        Job job = new Job("[AutoLogon] Keep-alive: " + destId) {
            @Override
            protected IStatus run(IProgressMonitor monitor) {
                if (monitor.isCanceled()) return Status.CANCEL_STATUS;

                if (ping(destId, monitor)) {
                    schedule(INTERVAL_MS);
                } else {
                    activeJobs.remove(destId);
                    Activator.info("[KeepAlive] Stopped for " + destId
                            + " (session no longer active)");
                }
                return Status.OK_STATUS;
            }
        };
        job.setSystem(true);
        job.setPriority(Job.DECORATE);
        activeJobs.put(destId, job);
        job.schedule(INTERVAL_MS);
        Activator.info("[KeepAlive] Started for " + destId);
    }

    public static void stop(String destId) {
        Job existing = activeJobs.remove(destId);
        if (existing != null) {
            existing.cancel();
        }
    }

    public static void stopAll() {
        activeJobs.forEach((id, job) -> job.cancel());
        activeJobs.clear();
    }

    private static boolean ping(String destId, IProgressMonitor monitor) {
        try {
            ISystemSessionFactory sessionFactory =
                    AdtSystemSessionFactory.createSystemSessionFactory();
            IStatelessSystemSession session =
                    sessionFactory.createStatelessSession(destId);
            session.setBackground(true);

            IRequestFactory reqFactory = AdtRequestFactory.createRequestFactory();
            IRequest request = reqFactory.createInstance(
                    IRequest.Method.GET, DISCOVERY_URI);

            session.sendRequest(monitor, request);
            Activator.debug("[KeepAlive] Ping OK for " + destId);
            return true;
        } catch (Exception e) {
            Activator.warn("[KeepAlive] Ping failed for " + destId
                    + ": " + e.getMessage());
            return false;
        }
    }
}
