// Kiểm image idp (CVE-2026-91403 — P2-T05 mục 7): in mọi CA mà TrustManager MẶC ĐỊNH của JVM tin, tức đúng cơ chế JSSE
// dùng cho kết nối TLS đi ra của Keycloak khi không cấu hình truststore-paths (javax.net.ssl.trustStore nếu có, rồi
// jssecacerts, rồi cacerts — không phụ thuộc đường dẫn hay alias). Dòng đầu (bắt đầu bằng '#'): java.home và
// javax.net.ssl.trustStore; mỗi dòng sau: SHA-256 của chứng chỉ (hex hoa, ngăn bằng ':'), tab, subject (RFC 2253).
// Chạy bằng source launcher của JDK 21 có sẵn trong image (không cần javac, không ghi file):
//   docker run --rm --network none --read-only -v "$PWD/infrastructure/docker/idp/TrustCheck.java:/check/TrustCheck.java:ro" \
//     --entrypoint java <image> -XX:-UsePerfData /check/TrustCheck.java
// Không nằm trong image: Dockerfile không chép file này (workflow images và người kiểm tay gắn vào lúc chạy).
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class TrustCheck {
    public static void main(String[] args) throws Exception {
        System.out.println("# java.home=" + System.getProperty("java.home")
                + " javax.net.ssl.trustStore=" + System.getProperty("javax.net.ssl.trustStore"));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);   // null = kho mặc định của JSSE
        HexFormat hex = HexFormat.ofDelimiter(":").withUpperCase();
        int n = 0;
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager x509) {
                for (X509Certificate c : x509.getAcceptedIssuers()) {
                    byte[] d = MessageDigest.getInstance("SHA-256").digest(c.getEncoded());
                    System.out.println(hex.formatHex(d) + "\t" + c.getSubjectX500Principal().getName());
                    n++;
                }
            }
        }
        if (n == 0) {
            throw new IllegalStateException("TrustManager mặc định không tin CA nào");
        }
    }
}
