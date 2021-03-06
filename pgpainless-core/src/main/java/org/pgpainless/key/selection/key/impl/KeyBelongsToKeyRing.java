/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.key.selection.key.impl;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.selection.key.PublicKeySelectionStrategy;

public class KeyBelongsToKeyRing {

    private static final Logger LOGGER = Logger.getLogger(KeyBelongsToKeyRing.class.getName());

    public static class PubkeySelectionStrategy extends PublicKeySelectionStrategy {

        private final PGPPublicKey masterKey;

        public PubkeySelectionStrategy(PGPPublicKey masterKey) {
            this.masterKey = masterKey;
        }

        @Override
        public boolean accept(@Nonnull PGPPublicKey key) {
            // Same key -> accept
            if (Arrays.equals(masterKey.getFingerprint(), key.getFingerprint())) {
                return true;
            }

            Iterator<PGPSignature> signatures = key.getSignaturesForKeyID(masterKey.getKeyID());
            while (signatures.hasNext()) {
                PGPSignature signature = signatures.next();
                if (signature.getSignatureType() == PGPSignature.SUBKEY_BINDING) {
                    try {
                        signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), masterKey);
                        return signature.verifyCertification(masterKey, key);
                    } catch (PGPException e) {
                        LOGGER.log(Level.WARNING, "Could not verify subkey signature of key " +
                                Long.toHexString(masterKey.getKeyID()) + " on key " + Long.toHexString(key.getKeyID()));

                        return false;
                    }
                }
            }
            return false;
        }
    }
}
