package ninja.abap.adt_auto_logon;

import org.eclipse.core.runtime.ILog;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Platform;
import org.eclipse.core.runtime.Status;
import org.eclipse.ui.plugin.AbstractUIPlugin;
import org.osgi.framework.BundleContext;

import ninja.abap.adt_auto_logon.handler.SessionKeepAlive;

public class Activator extends AbstractUIPlugin {

    public static final String PLUGIN_ID = "ninja.abap.adt_auto_logon";
    private static final boolean DEBUG = Boolean.getBoolean(PLUGIN_ID + ".debug");

    private static Activator instance;

    @Override
    public void start(BundleContext context) throws Exception {
        super.start(context);
        instance = this;
        log(IStatus.INFO, "ADT Auto-Logon plugin started");
    }

    @Override
    public void stop(BundleContext context) throws Exception {
        SessionKeepAlive.stopAll();
        instance = null;
        super.stop(context);
    }

    public static Activator getDefault() {
        return instance;
    }

    public static void log(int severity, String message) {
        ILog log = Platform.getLog(Activator.class);
        log.log(new Status(severity, PLUGIN_ID, message));
    }

    public static void log(int severity, String message, Throwable t) {
        ILog log = Platform.getLog(Activator.class);
        log.log(new Status(severity, PLUGIN_ID, message, t));
    }

    public static void debug(String message) {
        if (DEBUG) log(IStatus.INFO, message);
    }

    public static void info(String message) {
        log(IStatus.INFO, message);
    }

    public static void warn(String message) {
        log(IStatus.WARNING, message);
    }

    public static void error(String message, Throwable t) {
        log(IStatus.ERROR, message, t);
    }
}
