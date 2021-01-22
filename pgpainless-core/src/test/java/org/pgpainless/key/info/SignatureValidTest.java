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
