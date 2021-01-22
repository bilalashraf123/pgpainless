package org.pgpainless.encryption_signing;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.implementation.ImplementationFactory;

public class PainlessSignatureGenerator {

    public static PGPSignatureGenerator initSignatureGenerator(PGPPrivateKey privateKey, HashAlgorithm hashAlgorithm, SignatureType signatureType) throws PGPException {
        PGPContentSignerBuilder contentSignerBuilder = ImplementationFactory.getInstance().getPGPContentSignerBuilder(
                privateKey.getPublicKeyPacket().getAlgorithm(), hashAlgorithm.getAlgorithmId());
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder);
        signatureGenerator.init(signatureType.getCode(), privateKey);
        return signatureGenerator;
    }

    public static PGPSignature certifyUserId(PGPSignatureGenerator signatureGenerator,
                                             PGPPublicKey publicKey, String userId)
            throws PGPException {
        return signatureGenerator.generateCertification(userId, publicKey);
    }
}
