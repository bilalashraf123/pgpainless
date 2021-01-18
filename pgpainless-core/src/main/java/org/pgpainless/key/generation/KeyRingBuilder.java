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
package org.pgpainless.key.generation;


import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.pgpainless.algorithm.HashAlgorithm;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.provider.ProviderFactory;
import org.pgpainless.util.Passphrase;

public class KeyRingBuilder extends KeyArchetypes {

    private final Charset UTF8 = Charset.forName("UTF-8");

    private List<KeySpec> keySpecs = new ArrayList<>();
    private String userId;
    private Set<String> additionalUserIds = new LinkedHashSet<>();
    private Passphrase passphrase;

    @Override
    public KeyRingBuilderInterface withSubKey(@Nonnull KeySpec type) {
        KeyRingBuilder.this.keySpecs.add(type);
        return this;
    }

    @Override
    public WithPrimaryUserId withMasterKey(@Nonnull KeySpec spec) {
        verifyMasterKeyCanCertify(spec);

        KeyRingBuilder.this.keySpecs.add(0, spec);
        return new WithPrimaryUserIdImpl();
    }

    private void verifyMasterKeyCanCertify(KeySpec spec) {
        if (!hasCertifyOthersFlag(spec)) {
            throw new IllegalArgumentException("Certification Key MUST have KeyFlag CERTIFY_OTHER");
        }
        if (!keyIsCertificationCapable(spec)) {
            throw new IllegalArgumentException("Key algorithm " + spec.getKeyType().getName() + " is not capable of creating certifications.");
        }
    }

    private boolean hasCertifyOthersFlag(KeySpec keySpec) {
        int flags = keySpec.getSubpackets().getKeyFlags();
        return KeyFlag.hasKeyFlag(flags, KeyFlag.CERTIFY_OTHER);
    }

    private boolean keyIsCertificationCapable(KeySpec keySpec) {
        return keySpec.getKeyType().canCertify();
    }

    class WithPrimaryUserIdImpl implements WithPrimaryUserId {

        @Override
        public WithAdditionalUserIdOrPassphrase withPrimaryUserId(@Nonnull String userId) {
            KeyRingBuilder.this.userId = userId.trim();
            return new WithAdditionalUserIdOrPassphraseImpl();
        }

        @Override
        public WithAdditionalUserIdOrPassphrase withPrimaryUserId(@Nonnull byte[] userId) {
            return withPrimaryUserId(new String(userId, UTF8));
        }
    }

    class WithAdditionalUserIdOrPassphraseImpl implements WithAdditionalUserIdOrPassphrase {

        @Override
        public WithAdditionalUserIdOrPassphrase withAdditionalUserId(@Nonnull String userId) {
            String trimmed = userId.trim();
            if (KeyRingBuilder.this.userId.equals(trimmed)) {
                throw new IllegalArgumentException("Additional user-id MUST NOT be equal to primary user-id.");
            }
            KeyRingBuilder.this.additionalUserIds.add(trimmed);
            return this;
        }

        @Override
        public WithAdditionalUserIdOrPassphrase withAdditionalUserId(@Nonnull byte[] userId) {
            return withAdditionalUserId(new String(userId, UTF8));
        }

        @Override
        public Build withPassphrase(@Nonnull Passphrase passphrase) {
            KeyRingBuilder.this.passphrase = passphrase;
            return new BuildImpl();
        }

        @Override
        public Build withoutPassphrase() {
            KeyRingBuilder.this.passphrase = null;
            return new BuildImpl();
        }

        class BuildImpl implements Build {

            private PGPSignatureGenerator signatureGenerator;
            private PGPDigestCalculator digestCalculator;
            private PBESecretKeyEncryptor secretKeyEncryptor;

            @Override
            public PGPSecretKeyRing build() throws NoSuchAlgorithmException, PGPException,
                    InvalidAlgorithmParameterException {
                digestCalculator = buildDigestCalculator();
                secretKeyEncryptor = buildSecretKeyEncryptor();
                PBESecretKeyDecryptor secretKeyDecryptor = buildSecretKeyDecryptor();

                if (passphrase != null) {
                    passphrase.clear();
                }

                // First key is the Master Key
                KeySpec certKeySpec = keySpecs.remove(0);

                // Generate Master Key
                PGPKeyPair certKey = generateKeyPair(certKeySpec);
                PGPContentSignerBuilder signer = buildContentSigner(certKey);
                signatureGenerator = new PGPSignatureGenerator(signer);
                PGPSignatureSubpacketVector hashedSubPackets = certKeySpec.getSubpackets();

                // Generator which the user can get the key pair from
                PGPKeyRingGenerator ringGenerator = buildRingGenerator(certKey, signer, hashedSubPackets);

                addSubKeys(ringGenerator);

                // Generate secret key ring with only primary user id
                PGPSecretKeyRing secretKeyRing = ringGenerator.generateSecretKeyRing();

                Iterator<PGPSecretKey> secretKeys = secretKeyRing.getSecretKeys();

                // Attempt to add additional user-ids to the primary public key
                PGPPublicKey primaryPubKey = secretKeys.next().getPublicKey();
                PGPPrivateKey privateKey = secretKeyRing.getSecretKey().extractPrivateKey(secretKeyDecryptor);
                for (String additionalUserId : additionalUserIds) {
                    signatureGenerator.init(SignatureType.POSITIVE_CERTIFICATION.getCode(), privateKey);
                    PGPSignature additionalUserIdSignature =
                            signatureGenerator.generateCertification(additionalUserId, primaryPubKey);
                    primaryPubKey = PGPPublicKey.addCertification(primaryPubKey,
                            additionalUserId, additionalUserIdSignature);
                }

                // "reassemble" secret key ring with modified primary key
                PGPSecretKey primarySecKey = new PGPSecretKey(
                        privateKey,
                        primaryPubKey, digestCalculator, true, secretKeyEncryptor);
                List<PGPSecretKey> secretKeyList = new ArrayList<>();
                secretKeyList.add(primarySecKey);
                while (secretKeys.hasNext()) {
                    secretKeyList.add(secretKeys.next());
                }
                secretKeyRing = new PGPSecretKeyRing(secretKeyList);

                return secretKeyRing;
            }

            private PGPKeyRingGenerator buildRingGenerator(PGPKeyPair certKey,
                                                           PGPContentSignerBuilder signer,
                                                           PGPSignatureSubpacketVector hashedSubPackets)
                    throws PGPException {
                return new PGPKeyRingGenerator(
                        SignatureType.POSITIVE_CERTIFICATION.getCode(), certKey,
                        userId, digestCalculator,
                        hashedSubPackets, null, signer, secretKeyEncryptor);
            }

            private void addSubKeys(PGPKeyRingGenerator ringGenerator)
                    throws NoSuchAlgorithmException, PGPException, InvalidAlgorithmParameterException {
                for (KeySpec subKeySpec : keySpecs) {
                    PGPKeyPair subKey = generateKeyPair(subKeySpec);
                    if (subKeySpec.isInheritedSubPackets()) {
                        ringGenerator.addSubKey(subKey);
                    } else {
                        ringGenerator.addSubKey(subKey, subKeySpec.getSubpackets(), null);
                    }
                }
            }

            private PGPContentSignerBuilder buildContentSigner(PGPKeyPair certKey) {
                return ImplementationFactory.getInstance().getPGPContentSignerBuilder(
                        certKey.getPublicKey().getAlgorithm(),
                        HashAlgorithm.SHA512.getAlgorithmId());
            }

            private PBESecretKeyEncryptor buildSecretKeyEncryptor() {
                PBESecretKeyEncryptor encryptor = passphrase == null || passphrase.isEmpty() ?
                        null : // unencrypted key pair, otherwise AES-256 encrypted
                        ImplementationFactory.getInstance().getPBESecretKeyEncryptor(
                                SymmetricKeyAlgorithm.AES_256, digestCalculator, passphrase);
                return encryptor;
            }

            private PBESecretKeyDecryptor buildSecretKeyDecryptor() throws PGPException {
                PBESecretKeyDecryptor decryptor = passphrase == null || passphrase.isEmpty() ?
                        null :
                        ImplementationFactory.getInstance().getPBESecretKeyDecryptor(passphrase);
                return decryptor;
            }

            private PGPDigestCalculator buildDigestCalculator() throws PGPException {
                return ImplementationFactory.getInstance().getPGPDigestCalculator(HashAlgorithm.SHA1);
            }
        }
    }

    public static PGPKeyPair generateKeyPair(KeySpec spec)
            throws NoSuchAlgorithmException, PGPException,
            InvalidAlgorithmParameterException {
        KeyType type = spec.getKeyType();
        KeyPairGenerator certKeyGenerator = KeyPairGenerator.getInstance(type.getName(), ProviderFactory.getProvider());
        certKeyGenerator.initialize(type.getAlgorithmSpec());

        // Create raw Key Pair
        KeyPair keyPair = certKeyGenerator.generateKeyPair();

        // Form PGP key pair
        PGPKeyPair pgpKeyPair = ImplementationFactory.getInstance().getPGPKeyPair(type.getAlgorithm(), keyPair, new Date());

        return pgpKeyPair;
    }
}
