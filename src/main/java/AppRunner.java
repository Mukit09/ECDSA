import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AppRunner {
    public static void main(String[] args) {
        SignatureGenerator generator = new SignatureGenerator();
        generator.generateKeys();
    //    log.debug("PublicKey in generator: " + generator.getPublicKey().toString());
        generator.getData();
        generator.signData();
        log.debug("Signature bytes in generator: " + new String(generator.getSignatureBytes()));

        SignatureVerifier verifier = new SignatureVerifier(generator.getPublicKeyByte(),
                generator.getBufferData(), generator.getSignatureBytes());
        verifier.generatePublicKey();
    //    log.debug("PublicKey in verifier: " + verifier.getPublicKey().toString());
        verifier.getSignature();
        log.debug("Signature bytes in Verifier: " + new String(verifier.getSignatureByteData()));
        boolean isVerified = verifier.verify();
        log.debug("Signature Verification: " + isVerified);
    }
}
