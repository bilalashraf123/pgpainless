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
package org.pgpainless.key.selection.key.util;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.pgpainless.key.selection.key.PublicKeySelectionStrategy;
import org.pgpainless.key.selection.key.SecretKeySelectionStrategy;

public class And {

    public static class PubKeySelectionStrategy extends PublicKeySelectionStrategy {

        private final Set<PublicKeySelectionStrategy> strategies = new HashSet<>();

        public PubKeySelectionStrategy(@Nonnull PublicKeySelectionStrategy... strategies) {
            this.strategies.addAll(Arrays.asList(strategies));
        }

        @Override
        public boolean accept(PGPPublicKey key) {
            boolean accept = true;
            for (PublicKeySelectionStrategy strategy : strategies) {
                accept &= strategy.accept(key);
            }
            return accept;
        }
    }

    public static class SecKeySelectionStrategy extends SecretKeySelectionStrategy {

        private final Set<SecretKeySelectionStrategy> strategies = new HashSet<>();

        public SecKeySelectionStrategy(@Nonnull SecretKeySelectionStrategy... strategies) {
            this.strategies.addAll(Arrays.asList(strategies));
        }

        @Override
        public boolean accept(PGPSecretKey key) {
            boolean accept = true;
            for (SecretKeySelectionStrategy strategy : strategies) {
                accept &= strategy.accept(key);
            }
            return accept;
        }
    }

}
