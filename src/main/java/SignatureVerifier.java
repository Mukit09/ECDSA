import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

@Slf4j
@Getter
public class SignatureVerifier {
    private byte[] publicKeyByteArray;
    private byte[] data;
    private byte[] signatureByteData;
    private Signature signature;
    private PublicKey publicKey;

    SignatureVerifier(byte[] publicKeyByteArray, byte[] data, byte[] signatureByteData) {
        this.publicKeyByteArray = publicKeyByteArray;
        this.data = data;
        this.signatureByteData = signatureByteData;
    }

    public void generatePublicKey() {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyByteArray);
        try {
            KeyFactory factory = KeyFactory.getInstance("EC", "SunEC");
            publicKey = factory.generatePublic(pubKeySpec);
        } catch (Exception e) {
            log.error("Exception: ", e);
        }
    }

    public void getSignature() {
        try {
            this.signature = Signature.getInstance("SHA256withECDSA", "SunEC");
            signature.initVerify(publicKey);
            signature.update(this.data);
        } catch (Exception e) {
            log.error("Exception: ", e);
        }
    }

    public boolean verify() {
        try {
            boolean isVerified = signature.verify(signatureByteData);
            return isVerified;
        } catch (SignatureException e) {
            log.error("Exception: ", e);
        }
        return false;
    }
}
