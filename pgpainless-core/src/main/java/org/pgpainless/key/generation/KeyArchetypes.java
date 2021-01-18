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
package org.pgpainless.key.generation;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import javax.annotation.Nonnull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.ecc.EllipticCurve;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import org.pgpainless.key.generation.type.xdh.XDHCurve;
import org.pgpainless.key.util.UserId;
import org.pgpainless.util.Passphrase;

public abstract class KeyArchetypes implements KeyRingBuilderInterface {

    public PGPSecretKeyRing simpleRsaKeyRing(@Nonnull UserId userId, @Nonnull RsaLength length)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleRsaKeyRing(userId.toString(), length);
    }

    /**
     * Creates a simple, unencrypted RSA KeyPair of length {@code length} with user-id {@code userId}.
     * The KeyPair consists of a single RSA master key which is used for signing, encryption and certification.
     *
     * @param userId user id.
     * @param length length in bits.
     *
     * @return {@link PGPSecretKeyRing} containing the KeyPair.
     */
    public PGPSecretKeyRing simpleRsaKeyRing(@Nonnull String userId, @Nonnull RsaLength length)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleRsaKeyRing(userId, length, null);
    }

    public PGPSecretKeyRing simpleRsaKeyRing(@Nonnull UserId userId, @Nonnull RsaLength rsaLength, String password)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleRsaKeyRing(userId.toString(), rsaLength, password);
    }

    /**
     * Creates a simple RSA KeyPair of length {@code length} with user-id {@code userId}.
     * The KeyPair consists of a single RSA master key which is used for signing, encryption and certification.
     *
     * @param userId user id.
     * @param length length in bits.
     * @param password Password of the key. Can be null for unencrypted keys.
     *
     * @return {@link PGPSecretKeyRing} containing the KeyPair.
     */
    public PGPSecretKeyRing simpleRsaKeyRing(@Nonnull String userId, @Nonnull RsaLength length, String password)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyRingBuilderInterface.WithAdditionalUserIdOrPassphrase builder = this
                .withMasterKey(
                        KeySpec.getBuilder(KeyType.RSA(length))
                                .withKeyFlags(KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA, KeyFlag.ENCRYPT_COMMS)
                                .withDefaultAlgorithms())
                .withPrimaryUserId(userId);

        if (password == null) {
            return builder.withoutPassphrase().build();
        } else {
            return builder.withPassphrase(new Passphrase(password.toCharArray())).build();
        }
    }

    public PGPSecretKeyRing simpleEcKeyRing(@Nonnull UserId userId)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleEcKeyRing(userId.toString());
    }

    /**
     * Creates an unencrypted key ring consisting of an ECDSA master key and an ECDH sub-key.
     * The ECDSA master key is used for signing messages and certifying the sub key.
     * The ECDH sub-key is used for encryption of messages.
     *
     * @param userId user-id
     *
     * @return {@link PGPSecretKeyRing} containing the key pairs.
     */
    public PGPSecretKeyRing simpleEcKeyRing(@Nonnull String userId)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleEcKeyRing(userId, null);
    }

    public PGPSecretKeyRing simpleEcKeyRing(@Nonnull UserId userId, String password)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleEcKeyRing(userId.toString(), password);
    }

    /**
     * Creates a key ring consisting of an ECDSA master key and an ECDH sub-key.
     * The ECDSA master key is used for signing messages and certifying the sub key.
     * The ECDH sub-key is used for encryption of messages.
     *
     * Both keys will use P-256 as underlying curve.
     *
     * @param userId user-id
     * @param password Password of the private key. Can be null for an unencrypted key.
     *
     * @return {@link PGPSecretKeyRing} containing the key pairs.
     */
    public PGPSecretKeyRing simpleEcKeyRing(@Nonnull String userId, String password)
            throws PGPException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyRingBuilderInterface.WithAdditionalUserIdOrPassphrase builder = this
                .withSubKey(
                        KeySpec.getBuilder(KeyType.ECDH(EllipticCurve._P256))
                                .withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
                                .withDefaultAlgorithms())
                .withMasterKey(
                        KeySpec.getBuilder(KeyType.ECDSA(EllipticCurve._P256))
                                .withKeyFlags(KeyFlag.AUTHENTICATION, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                                .withDefaultAlgorithms())
                .withPrimaryUserId(userId);

        if (password == null) {
            return builder.withoutPassphrase().build();
        } else {
            return builder.withPassphrase(new Passphrase(password.toCharArray())).build();
        }
    }

    public PGPSecretKeyRing simpleCurve25519KeyRing(String userId)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleCurve25519KeyRing(userId, null);
    }

    public PGPSecretKeyRing simpleCurve25519KeyRing(@Nonnull UserId userId, String password)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        return simpleCurve25519KeyRing(userId.toString(), password);
    }

    public PGPSecretKeyRing simpleCurve25519KeyRing(@Nonnull String userId, String password)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException {
        KeyRingBuilderInterface.WithAdditionalUserIdOrPassphrase builder = this
                .withSubKey(
                        KeySpec.getBuilder(KeyType.XDH(XDHCurve._X25519))
                                .withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
                                .withDefaultAlgorithms())
                .withMasterKey(
                        KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                                .withKeyFlags(KeyFlag.AUTHENTICATION, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                                .withDefaultAlgorithms())
                .withPrimaryUserId(userId);

        if (password == null) {
            return builder.withoutPassphrase().build();
        } else {
            return builder.withPassphrase(new Passphrase(password.toCharArray())).build();
        }
    }
}
