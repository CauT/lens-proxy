package io.lens.proxyprobe;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.util.Base64;
import android.widget.TextView;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.json.JSONObject;
import org.json.JSONArray;

/** Real Android framework client. No host proxy, global trust, or trust-all hooks. */
public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        TextView view = new TextView(this);
        view.setPadding(24, 48, 24, 24);
        view.setText("Lens Android proxy probe\nRunning on Android " + Build.VERSION.RELEASE);
        setContentView(view);
        final String encoded = getIntent().getStringExtra("config");
        if (encoded == null) { view.setText("Launch the acceptance runner to send a request."); return; }
        new Thread(() -> {
            try {
                JSONObject config = new JSONObject(new String(Base64.decode(encoded, Base64.DEFAULT), StandardCharsets.UTF_8));
                String token = config.getString("token");
                if (!token.matches("[a-f0-9]{32}")) throw new IllegalArgumentException("Invalid result token");
                JSONObject result = request(config);
                File path = new File(getFilesDir(), "result-" + token + ".json");
                try (FileOutputStream output = new FileOutputStream(path)) {
                    output.write(result.toString().getBytes(StandardCharsets.UTF_8));
                }
                runOnUiThread(() -> view.setText("Lens Android proxy probe\n" + result.toString()));
            } catch (Exception failure) {
                runOnUiThread(() -> view.setText("Probe setup failed: " + failure));
            }
        }, "lens-android-probe").start();
    }

    private static byte[] read(InputStream input) throws Exception {
        if (input == null) return new byte[0];
        try (InputStream stream = input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            for (int count; (count = stream.read(buffer)) != -1;) {
                if (output.size() + count > 1024 * 1024) throw new IllegalArgumentException("Probe response exceeds 1 MiB");
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    private static JSONObject request(JSONObject config) throws Exception {
        JSONObject result = new JSONObject();
        result.put("platform", "Android"); result.put("release", Build.VERSION.RELEASE);
        result.put("sdk", Build.VERSION.SDK_INT); result.put("fingerprint", Build.FINGERPRINT);
        result.put("token", config.getString("token")); result.put("url", config.getString("url"));
        HttpURLConnection connection = null;
        try {
            if (config.optString("transport", "http").equals("proxy-state")) {
                result.put("selectedProxies", ProxySelector.getDefault().select(new URI(config.getString("url"))).toString());
                return result;
            }
            if (config.optString("transport", "http").equals("udp")) {
                JSONArray datagrams = config.getJSONArray("datagramsBase64");
                if (datagrams.length() < 1 || datagrams.length() > 32) throw new IllegalArgumentException("Use 1–32 UDP datagrams");
                JSONArray responses = new JSONArray();
                result.put("transport", "udp"); result.put("datagramsBase64", responses);
                result.put("sentDatagrams", 0);
                int total = 0;
                try (DatagramSocket stream = new DatagramSocket()) {
                    stream.setSendBufferSize(131072); stream.setReceiveBufferSize(131072); stream.setSoTimeout(8000);
                    InetAddress destination = InetAddress.getByName(config.getString("proxyHost"));
                    int port = config.getInt("proxyPort");
                    // Android 15's connected PlainDatagramSocketImpl passes a
                    // null destination into IoBridge, whose empty-send branch
                    // returns without a syscall. An explicit destination keeps
                    // this probe generating actual zero-byte UDP datagrams.
                    result.put("socketMode", "unconnected-explicit-destination");
                    for (int index = 0; index < datagrams.length(); index++) {
                        byte[] body = Base64.decode(datagrams.getString(index), Base64.DEFAULT);
                        total += body.length;
                        if (body.length > 65507 || total > 1024 * 1024) throw new IllegalArgumentException("UDP probe payload limit exceeded");
                        result.put("attemptedDatagram", index);
                        stream.send(new DatagramPacket(body, body.length, destination, port));
                        result.put("sentDatagrams", index + 1);
                        byte[] buffer = new byte[65535];
                        DatagramPacket packet = new DatagramPacket(buffer, buffer.length); stream.receive(packet);
                        if (!destination.equals(packet.getAddress()) || packet.getPort() != port) throw new IllegalArgumentException("UDP probe received an unexpected peer");
                        responses.put(Base64.encodeToString(packet.getData(), packet.getOffset(), packet.getLength(), Base64.NO_WRAP));
                    }
                    result.put("localPort", stream.getLocalPort());
                }
                result.put("transport", "udp"); result.put("datagramsBase64", responses);
                result.put("peerHost", config.getString("proxyHost")); result.put("peerPort", config.getInt("proxyPort"));
                return result;
            }
            result.put("trustMode", config.has("anchorDERBase64") ? "session-anchor" : "system-default");
            result.put("proxyMode", config.optString("proxyMode", "explicit"));
            URL url = new URL(config.getString("url"));
            if (config.optString("proxyMode", "explicit").equals("system")) {
                result.put("selectedProxies", ProxySelector.getDefault().select(new URI(url.toString())).toString());
                connection = (HttpURLConnection) url.openConnection();
            } else {
                String host = config.getString("proxyHost"); int port = config.getInt("proxyPort");
                result.put("proxyHost", host); result.put("proxyPort", port);
                connection = (HttpURLConnection) url.openConnection(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port)));
            }
            connection.setConnectTimeout(5000); connection.setReadTimeout(8000);
            connection.setInstanceFollowRedirects(false); connection.setUseCaches(false);
            if (connection instanceof HttpsURLConnection && config.has("anchorDERBase64")) {
                byte[] der = Base64.decode(config.getString("anchorDERBase64"), Base64.DEFAULT);
                KeyStore anchors = KeyStore.getInstance(KeyStore.getDefaultType()); anchors.load(null, null);
                anchors.setCertificateEntry("lens-test", CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der)));
                TrustManagerFactory manager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); manager.init(anchors);
                SSLContext tls = SSLContext.getInstance("TLS"); tls.init(null, manager.getTrustManagers(), null);
                ((HttpsURLConnection) connection).setSSLSocketFactory(tls.getSocketFactory());
                // Preserve Android's hostname verifier and actual chain/validity evaluation.
            }
            String method = config.optString("method", "POST"); connection.setRequestMethod(method);
            connection.setRequestProperty("X-Lens-Android-Probe", config.getString("token"));
            connection.setRequestProperty("Content-Type", "application/octet-stream");
            byte[] body = Base64.decode(config.optString("bodyBase64", ""), Base64.DEFAULT);
            if (!method.equals("GET")) {
                connection.setDoOutput(true); connection.setFixedLengthStreamingMode(body.length);
                try (java.io.OutputStream output = connection.getOutputStream()) { output.write(body); }
            }
            int status = connection.getResponseCode(); result.put("status", status);
            result.put("bodyBase64", Base64.encodeToString(read(status >= 400 ? connection.getErrorStream() : connection.getInputStream()), Base64.NO_WRAP));
            JSONObject headers = new JSONObject();
            for (java.util.Map.Entry<String, java.util.List<String>> entry : connection.getHeaderFields().entrySet()) {
                if (entry.getKey() != null) headers.put(entry.getKey(), new JSONArray(entry.getValue()));
            }
            result.put("responseHeaders", headers);
            if (connection instanceof HttpsURLConnection) {
                byte[] leaf = ((HttpsURLConnection) connection).getServerCertificates()[0].getEncoded();
                StringBuilder hex = new StringBuilder();
                for (byte value : MessageDigest.getInstance("SHA-256").digest(leaf)) hex.append(String.format("%02x", value & 255));
                result.put("leafSHA256", hex.toString());
            }
        } catch (Exception failure) {
            result.put("errorClass", failure.getClass().getName()); result.put("error", failure.toString());
            StringBuilder causes = new StringBuilder();
            for (Throwable cause = failure; cause != null; cause = cause.getCause()) causes.append(cause.getClass().getName()).append(": ").append(cause.getMessage()).append("\n");
            result.put("causes", causes.toString());
        } finally { if (connection != null) connection.disconnect(); }
        return result;
    }
}
