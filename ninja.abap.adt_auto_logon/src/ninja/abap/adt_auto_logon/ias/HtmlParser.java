package ninja.abap.adt_auto_logon.ias;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Regex-based HTML parser for IAS login / SAML / OAuth forms. */
public final class HtmlParser {

    private static final Pattern HIDDEN_INPUT = Pattern.compile(
            "<input[^>]*type=[\"']hidden[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern NAME_ATTR = Pattern.compile(
            "name=[\"']([^\"']+)[\"']");
    private static final Pattern VALUE_ATTR = Pattern.compile(
            "value=[\"']([^\"']*?)[\"']");
    private static final Pattern FORM_TAG = Pattern.compile(
            "<form[\\s\\S]*?</form>", Pattern.CASE_INSENSITIVE);

    private HtmlParser() {}

    public static String decodeEntities(String s) {
        if (s == null) return null;
        StringBuilder sb = new StringBuilder(s.length());
        Matcher hex = Pattern.compile("&#x([0-9a-fA-F]+);").matcher(s);
        int last = 0;
        while (hex.find()) {
            sb.append(s, last, hex.start());
            sb.append((char) Integer.parseInt(hex.group(1), 16));
            last = hex.end();
        }
        sb.append(s, last, s.length());
        String r = sb.toString();

        sb.setLength(0);
        Matcher dec = Pattern.compile("&#(\\d+);").matcher(r);
        last = 0;
        while (dec.find()) {
            sb.append(r, last, dec.start());
            sb.append((char) Integer.parseInt(dec.group(1)));
            last = dec.end();
        }
        sb.append(r, last, r.length());

        return sb.toString()
                .replace("&amp;", "&")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"");
    }

    public static Map<String, String> hiddenFields(String html) {
        Map<String, String> fields = new LinkedHashMap<>();
        Matcher m = HIDDEN_INPUT.matcher(html);
        while (m.find()) {
            String tag = m.group();
            Matcher nm = NAME_ATTR.matcher(tag);
            Matcher vm = VALUE_ATTR.matcher(tag);
            if (nm.find()) {
                fields.put(nm.group(1), vm.find() ? decodeEntities(vm.group(1)) : "");
            }
        }
        return fields;
    }

    public static String inputValue(String html, String name) {
        Pattern re = Pattern.compile(
                "<input[^>]*name=[\"']" + Pattern.quote(name) + "[\"'][^>]*>",
                Pattern.CASE_INSENSITIVE);
        Matcher m = re.matcher(html);
        if (!m.find()) return null;
        Matcher v = VALUE_ATTR.matcher(m.group());
        return v.find() ? decodeEntities(v.group(1)) : null;
    }

    public static String attribute(String html, String attr) {
        Matcher m = Pattern.compile(attr + "=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)
                .matcher(html);
        return m.find() ? decodeEntities(m.group(1)) : null;
    }

    public static String firstForm(String html) {
        Matcher m = FORM_TAG.matcher(html);
        return m.find() ? m.group() : null;
    }

    public static boolean isLoginForm(String html) {
        return ci("name=[\"']j_password[\"']").matcher(html).find()
                && !ci("name=[\"']SAMLResponse[\"']").matcher(html).find();
    }

    public static boolean isTwoFaChallenge(String html) {
        return ci("name=[\"']j_otpcode[\"']").matcher(html).find()
                || ci("name=[\"']passcode[\"']").matcher(html).find()
                || ci("Two-Factor Authentication").matcher(html).find();
    }

    public static boolean isSamlAutoSubmit(String html) {
        if (ci("name=[\"']j_password[\"']").matcher(html).find()) return false;
        return ci("name=[\"']SAMLResponse[\"']").matcher(html).find()
                || ci("name=[\"']SAMLRequest[\"']").matcher(html).find();
    }

    public static boolean isUnsupportedChallenge(String html) {
        return ci("webauthn|security key|fido").matcher(html).find()
                || ci("push notification|approve on").matcher(html).find();
    }

    private static Pattern ci(String regex) {
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    }
}
