package org.pgpainless.key.info;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.util.Passphrase;

public class SignatureValidTest {

    @Test
    public void test() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        PGPSecretKey secretKey = secretKeys.getSecretKey();

        PGPSignature signature = createSelfSignature(secretKey, SignatureType.KEY_REVOCATION);
    }

    public static PGPSignature createSelfSignature(PGPSecretKey issuer, SignatureType type) throws PGPException {
        PGPSignatureGenerator generator = new PGPSignatureGenerator(ImplementationFactory.getInstance()
                .getPGPContentSignerBuilder(issuer.getPublicKey().getAlgorithm(), HashAlgorithm.SHA512.getAlgorithmId()));
        PGPPrivateKey privateKey = issuer.extractPrivateKey(PasswordBasedSecretKeyRingProtector.forKey(issuer,
                Passphrase.fromPassword(TestKeys.CRYPTIE_PASSWORD)).getDecryptor(issuer.getKeyID()));
        generator.init(type.getCode(), privateKey);

        return generator.generateCertification(issuer.getPublicKey());
    }
}
