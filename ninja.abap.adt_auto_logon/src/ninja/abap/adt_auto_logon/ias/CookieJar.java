package ninja.abap.adt_auto_logon.ias;

import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/** Per-hostname cookie store for headless HTTP navigation. */
public final class CookieJar {

    private final Map<String, Map<String, String>> jar = new ConcurrentHashMap<>();

    public void store(String hostname, HttpResponse<?> response) {
        List<String> setCookies = response.headers().allValues("set-cookie");
        if (setCookies.isEmpty()) return;

        Map<String, String> host = jar.computeIfAbsent(hostname, k -> new LinkedHashMap<>());
        for (String header : setCookies) {
            String pair = header.split(";", 2)[0];
            int eq = pair.indexOf('=');
            if (eq > 0) {
                host.put(pair.substring(0, eq).trim(), pair.substring(eq + 1));
            }
        }
    }

    public String get(String hostname) {
        Map<String, String> host = jar.get(hostname);
        if (host == null || host.isEmpty()) return "";
        return host.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining("; "));
    }
}
