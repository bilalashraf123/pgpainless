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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;

import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.generation.KeySpec;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHCurve;
import org.pgpainless.key.protection.PasswordBasedSecretKeyRingProtector;
import org.pgpainless.key.protection.SecretKeyRingProtector;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.key.util.RevocationAttributes;
import org.pgpainless.key.util.SignatureUtils;

public class UserIdRevocationTest {

    @Test
    public void test() throws IOException, PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InterruptedException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(KeyType.XDH(XDHCurve._X25519))
                        .withKeyFlags(KeyFlag.ENCRYPT_COMMS)
                        .withDefaultAlgorithms())
                .withMasterKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                        .withKeyFlags(KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER)
                        .withDefaultAlgorithms())
                .withPrimaryUserId("primary@key.id")
                .withAdditionalUserId("secondary@key.id")
                .withoutPassphrase()
                .build();

        Thread.sleep(1000);

        // make a copy with revoked subkey
        PGPSecretKeyRing revoked = PGPainless.modifyKeyRing(secretKeys)
                .revokeUserIdOnAllSubkeys("secondary@key.id", new UnprotectedKeysProtector())
                .done();

        KeyRingInfo info = PGPainless.inspectKeyRing(revoked);
        List<String> userIds = info.getUserIds();
        assertEquals(Arrays.asList("primary@key.id", "secondary@key.id"), userIds);
        assertTrue(info.isUserIdValid("primary@key.id"));
        assertFalse(info.isUserIdValid("sedondary@key.id"));
        assertFalse(info.isUserIdValid("tertiary@key.id"));

        info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.isUserIdValid("secondary@key.id")); // key on original secret key ring is still valid

        revoked = PGPainless.modifyKeyRing(secretKeys)
                .revokeUserId("secondary@key.id", secretKeys.getSecretKey().getKeyID(), new UnprotectedKeysProtector())
                .done();
        info = PGPainless.inspectKeyRing(revoked);
        userIds = info.getUserIds();
        assertEquals(Arrays.asList("primary@key.id", "secondary@key.id"), userIds);
        assertTrue(info.isUserIdValid("primary@key.id"));
        assertFalse(info.isUserIdValid("sedondary@key.id"));
        assertFalse(info.isUserIdValid("tertiary@key.id"));
    }

    @Test
    public void testRevocationWithRevocationReason() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, InterruptedException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .withSubKey(KeySpec.getBuilder(KeyType.XDH(XDHCurve._X25519))
                        .withKeyFlags(KeyFlag.ENCRYPT_COMMS)
                        .withDefaultAlgorithms())
                .withMasterKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519))
                        .withKeyFlags(KeyFlag.SIGN_DATA, KeyFlag.CERTIFY_OTHER)
                        .withDefaultAlgorithms())
                .withPrimaryUserId("primary@key.id")
                .withAdditionalUserId("secondary@key.id")
                .withoutPassphrase()
                .build();

        Thread.sleep(1000);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .revokeUserIdOnAllSubkeys("secondary@key.id", new UnprotectedKeysProtector(),
                        RevocationAttributes.createCertificateRevocation()
                                .withReason(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID)
                                .withDescription("I lost my mail password"))
                .done();
        PGPSignature signature = SignatureUtils.getLatestSelfSignatureForUserId(secretKeys.getPublicKey(), "secondary@key.id");
        RevocationReason reason = (RevocationReason) signature.getHashedSubPackets()
                .getSubpacket(SignatureSubpacketTags.REVOCATION_REASON);
        assertNotNull(reason);
        assertEquals("I lost my mail password", reason.getRevocationDescription());
    }

    @Test
    public void unknownKeyThrowsIllegalArgumentException() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys.getSecretKey(), TestKeys.CRYPTIE_PASSPHRASE);

        assertThrows(IllegalArgumentException.class, () -> PGPainless.modifyKeyRing(secretKeys)
                .revokeUserId("cryptie@encrypted.key", 1L, protector));
        assertThrows(IllegalArgumentException.class, () -> PGPainless.modifyKeyRing(secretKeys)
                .revokeUserId("cryptie@encrypted.key", TestKeys.EMIL_FINGERPRINT, protector));
    }

    @Test
    public void unknownUserIdThrowsNoSuchElementException() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys.getSecretKey(), TestKeys.CRYPTIE_PASSPHRASE);

        assertThrows(NoSuchElementException.class, () -> PGPainless.modifyKeyRing(secretKeys)
                .revokeUserId("invalid@user.id", TestKeys.CRYPTIE_FINGERPRINT, protector));
        assertThrows(NoSuchElementException.class, () -> PGPainless.modifyKeyRing(secretKeys)
                .revokeUserId("invalid@user.id", TestKeys.CRYPTIE_KEY_ID, protector));
    }

    @Test
    public void invalidRevocationReasonThrowsIllegalArgumentException() throws IOException, PGPException {
        PGPSecretKeyRing secretKeys = TestKeys.getCryptieSecretKeyRing();
        SecretKeyRingProtector protector = PasswordBasedSecretKeyRingProtector
                .forKey(secretKeys.getSecretKey(), TestKeys.CRYPTIE_PASSPHRASE);

        assertThrows(IllegalArgumentException.class, () -> PGPainless.modifyKeyRing(secretKeys)
                .revokeUserId("cryptie@encrypted.key", secretKeys.getSecretKey().getKeyID(), protector,
                        RevocationAttributes.createKeyRevocation().withReason(RevocationAttributes.Reason.KEY_RETIRED)
                .withDescription("This is not a valid certification revocation reason.")));
    }
}
