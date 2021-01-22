package org.pgpainless;

import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public final class Policy {

    private static Policy INSTANCE;

    private HashAlgorithm signatureHashAlgorithm = HashAlgorithm.SHA512;
    private SymmetricKeyAlgorithm symmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES_256;

    private Policy() {
    }

    public static Policy getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new Policy();
        }
        return INSTANCE;
    }

    public void setDefaultSignatureHashAlgorithm(HashAlgorithm hashAlgorithm) {
        if (hashAlgorithm == null) {
            throw new IllegalArgumentException("HashAlgorithm cannot be null.");
        }
        this.signatureHashAlgorithm = hashAlgorithm;
    }

    public HashAlgorithm getDefaultSignatureHashAlgorithm() {
        return signatureHashAlgorithm;
    }

    public void setDefaultKeyEncryptionAlgorithm(SymmetricKeyAlgorithm symmetricKeyAlgorithm) {
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
    }

    public SymmetricKeyAlgorithm getDefaultSymmetricKeyAlgorithm() {
        return symmetricKeyAlgorithm;
    }
}
