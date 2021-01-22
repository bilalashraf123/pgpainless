package org.pgpainless.key.modification;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.protection.UnprotectedKeysProtector;
import org.pgpainless.util.ArmorUtils;

public class OldSignatureSubpacketsArePreservedOnNewSig {

    @Test
    public void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, PGPException, InterruptedException, IOException {
        PGPSecretKeyRing secretKeys = PGPainless.generateKeyRing()
                .simpleEcKeyRing("Alice <alice@wonderland.lit>");

        System.out.println(ArmorUtils.toAsciiArmoredString(secretKeys));

        OpenPgpV4Fingerprint subkeyFingerprint = new OpenPgpV4Fingerprint(PGPainless.inspectKeyRing(secretKeys).getPublicKeys().get(1));

        PGPSignature oldSignature = PGPainless.inspectKeyRing(secretKeys).getLatestValidSelfOrBindingSignature(subkeyFingerprint);
        PGPSignatureSubpacketVector oldPackets = oldSignature.getHashedSubPackets();

        assertEquals(0, oldPackets.getKeyExpirationTime());

        Thread.sleep(1000);
        secretKeys = PGPainless.modifyKeyRing(secretKeys)
                .setExpirationDate(subkeyFingerprint, new Date(), new UnprotectedKeysProtector())
                .done();
        PGPSignature newSignature = PGPainless.inspectKeyRing(secretKeys).getLatestValidSelfOrBindingSignature(subkeyFingerprint);
        PGPSignatureSubpacketVector newPackets = newSignature.getHashedSubPackets();

        assertNotEquals(0, newPackets.getKeyExpirationTime());

        assertArrayEquals(oldPackets.getPreferredHashAlgorithms(), newPackets.getPreferredHashAlgorithms());
    }
}
