package ninja.abap.adt_auto_logon.preferences;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.PBEKeySpec;

import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.IPath;
import org.eclipse.equinox.security.storage.ISecurePreferences;
import org.eclipse.equinox.security.storage.SecurePreferencesFactory;
import org.eclipse.equinox.security.storage.StorageException;
import org.eclipse.equinox.security.storage.provider.IProviderHints;

import ninja.abap.adt_auto_logon.Activator;

/**
 * Encrypted credential persistence using Eclipse Secure Storage.
 *
 * Uses a workspace-local storage file with PBE encryption instead of
 * the global default (which relies on OS-specific providers like Windows DPAPI
 * that can fail with "Key not valid for use in specified state").
 *
 * Layout:
 *   /ninja.abap.adt_auto_logon/{destinationId}/username
 *   /ninja.abap.adt_auto_logon/{destinationId}/password
 */
public final class CredencialStore {

    private static final String ROOT_NODE = "ninja.abap.adt_auto_logon";
    private static final String KEY_USERNAME = "username";
    private static final String KEY_PASSWORD = "password";

    private static volatile ISecurePreferences securePrefs;

    private CredencialStore() {}

    public static void save(String destinationId, String username, String password)
            throws StorageException, IOException {
        ISecurePreferences node = getNode(destinationId);
        node.put(KEY_USERNAME, username, false);
        node.put(KEY_PASSWORD, password, true);
        node.flush();
    }

    public static String getUsername(String destinationId) {
        try {
            return getNode(destinationId).get(KEY_USERNAME, "");
        } catch (StorageException e) {
            Activator.error("Failed to read username for " + destinationId, e);
            return "";
        }
    }

    public static String getPassword(String destinationId) {
        try {
            return getNode(destinationId).get(KEY_PASSWORD, "");
        } catch (StorageException e) {
            Activator.error("Failed to read password for " + destinationId, e);
            return "";
        }
    }

    public static boolean hasCredentials(String destinationId) {
        String u = getUsername(destinationId);
        String p = getPassword(destinationId);
        return u != null && !u.isEmpty() && p != null && !p.isEmpty();
    }

    public static void remove(String destinationId) {
        try {
            ISecurePreferences root = getSecurePreferences().node(ROOT_NODE);
            if (root.nodeExists(destinationId)) {
                root.node(destinationId).removeNode();
                root.flush();
            }
        } catch (IOException e) {
            Activator.error("Failed to remove credentials for " + destinationId, e);
        }
    }

    private static ISecurePreferences getNode(String destinationId) {
        return getSecurePreferences()
                .node(ROOT_NODE)
                .node(destinationId);
    }

    private static ISecurePreferences getSecurePreferences() {
        ISecurePreferences prefs = securePrefs;
        if (prefs != null) return prefs;

        synchronized (CredencialStore.class) {
            prefs = securePrefs;
            if (prefs != null) return prefs;

            try {
                IPath wsPath = ResourcesPlugin.getWorkspace().getRoot().getLocation()
                        .append(".metadata/.plugins/ninja.abap.adt_auto_logon");
                wsPath.toFile().mkdirs();
                URL url = wsPath.append("secure_storage").toFile().toURI().toURL();

                Map<String, Object> options = new HashMap<>();
                options.put(IProviderHints.PROMPT_USER, Boolean.FALSE);
                options.put(IProviderHints.DEFAULT_PASSWORD,
                        new PBEKeySpec(deriveEncryptionPassword()));

                prefs = SecurePreferencesFactory.open(url, options);
                Activator.debug("[AutoLogon] Opened workspace-local secure storage at " + url);
            } catch (Exception e) {
                Activator.warn("[AutoLogon] Could not open workspace secure storage, "
                        + "using default: " + e.getMessage());
                prefs = SecurePreferencesFactory.getDefault();
            }

            securePrefs = prefs;
            return prefs;
        }
    }

    private static char[] deriveEncryptionPassword() {
        String userName = System.getProperty("user.name", "eclipse");
        String userHome = System.getProperty("user.home", "");
        return (userName + "@" + userHome).toCharArray();
    }
}
