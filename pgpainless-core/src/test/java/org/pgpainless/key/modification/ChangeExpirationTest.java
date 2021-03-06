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
package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.TestKeys;
import org.pgpainless.key.info.KeyRingInfo;
import org.pgpainless.key.protection.UnprotectedKeysProtector;

import java.io.IOException;
import java.util.Date;

public class ChangeExpirationTest {

    private final OpenPgpV4Fingerprint subKeyFingerprint = new OpenPgpV4Fingerprint("F73FDE6439ABE210B1AF4EDD273EF7A0C749807B");

    @Test
    public void setExpirationDateAndThenUnsetIt_OnPrimaryKey() throws PGPException, IOException, InterruptedException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        KeyRingInfo sInfo = PGPainless.inspectKeyRing(secretKeys);

        assertNull(sInfo.getExpirationDate());
        assertNull(sInfo.getExpirationDate(subKeyFingerprint));

        Date date = new Date(1606493432000L);
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(date, new UnprotectedKeysProtector()).done();
        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNotNull(sInfo.getExpirationDate());
        assertEquals(date.getTime(), sInfo.getExpirationDate().getTime());
        // subkey unchanged
        assertNull(sInfo.getExpirationDate(subKeyFingerprint));

        // We need to wait for one second as OpenPGP signatures have coarse-grained (up to a second)
        // accuracy. Creating two signatures within a short amount of time will make the second one
        // "invisible"
        Thread.sleep(1100);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(null, new UnprotectedKeysProtector()).done();

        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNull(sInfo.getExpirationDate());
        assertNull(sInfo.getExpirationDate(subKeyFingerprint));
    }

    @Test
    public void setExpirationDateAndThenUnsetIt_OnSubkey() throws PGPException, IOException, InterruptedException {
        PGPSecretKeyRing secretKeys = TestKeys.getEmilSecretKeyRing();
        KeyRingInfo sInfo = PGPainless.inspectKeyRing(secretKeys);

        assertNull(sInfo.getExpirationDate(subKeyFingerprint));
        assertNull(sInfo.getExpirationDate());

        Date date = new Date(1606493432000L);
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(subKeyFingerprint, date, new UnprotectedKeysProtector()).done();
        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNotNull(sInfo.getExpirationDate(subKeyFingerprint));
        assertEquals(date.getTime(), sInfo.getExpirationDate(subKeyFingerprint).getTime());
        assertNull(sInfo.getExpirationDate());

        // We need to wait for one second as OpenPGP signatures have coarse-grained (up to a second)
        // accuracy. Creating two signatures within a short amount of time will make the second one
        // "invisible"
        Thread.sleep(1100);

        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(subKeyFingerprint, null, new UnprotectedKeysProtector()).done();

        sInfo = PGPainless.inspectKeyRing(secretKeys);
        assertNull(sInfo.getExpirationDate(subKeyFingerprint));
        assertNull(sInfo.getExpirationDate());
    }
}
