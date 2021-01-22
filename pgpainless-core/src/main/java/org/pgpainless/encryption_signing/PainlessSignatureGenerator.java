/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.encryption_signing;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
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
