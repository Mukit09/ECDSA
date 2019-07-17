import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.security.*;

@Slf4j
@Getter
@Setter
public class SignatureGenerator {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Signature signature;
    private byte[] bufferData;
    private byte[] signatureBytes;
    private byte[] publicKeyByte;

    public void generateKeys() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "SunEC");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            generator.initialize(256, random);
            KeyPair pair = generator.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();
            this.setPublicKeyByte(publicKey.getEncoded());
            this.setPrivateKey(privateKey);
            this.setPublicKey(publicKey);
        } catch (Exception e) {
            log.error("Exception: ", e);
        }
    }

    public void signData() {
        try {
            this.signature = Signature.getInstance("SHA256withECDSA", "SunEC");
            this.signature.initSign(this.getPrivateKey());
            this.signature.update(this.bufferData);
            this.signatureBytes = signature.sign();
        } catch (Exception e) {
            log.error("Exception: ", e);
        }
    }

    public void getData() {
        String data = "My name is Mukit";
        this.bufferData = data.getBytes();
    }
}
