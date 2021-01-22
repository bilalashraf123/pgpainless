/*
 * Copyright 2020 Paul Schaub.
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.algorithm.SignatureType;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.implementation.ImplementationFactory;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.util.KeyRingUtils;

/**
 * Utility class to quickly extract certain information from a {@link PGPPublicKeyRing}/{@link PGPSecretKeyRing}.
 */
public class KeyRingInfo {

    private static final Pattern PATTERN_EMAIL = Pattern.compile("[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}");

    private final PGPKeyRing keys;

    public KeyRingInfo(PGPKeyRing keys) {
        this.keys = keys;
    }

    /**
     * Return the first {@link PGPPublicKey} of this key ring.
     *
     * @return public key
     */
    public PGPPublicKey getPublicKey() {
        return keys.getPublicKey();
    }

    public PGPPublicKey getPublicKey(OpenPgpV4Fingerprint fingerprint) {
        return getPublicKey(fingerprint.getKeyId());
    }

    public PGPPublicKey getPublicKey(long keyId) {
        return keys.getPublicKey(keyId);
    }

    public static PGPPublicKey getPublicKey(PGPKeyRing keyRing, long keyId) {
        return keyRing.getPublicKey(keyId);
    }

    /**
     * Return all {@link PGPPublicKey PGPPublicKeys} of this key ring.
     * The first key in the list being the primary key.
     * Note that the list is unmodifiable.
     *
     * @return list of public keys
     */
    public List<PGPPublicKey> getPublicKeys() {
        List<PGPPublicKey> list = new ArrayList<>();
        Iterator<PGPPublicKey> iterator = keys.getPublicKeys();
        while (iterator.hasNext()) {
            list.add(iterator.next());
        }
        return Collections.unmodifiableList(list);
    }

    /**
     * Return the primary {@link PGPSecretKey} of this key ring or null if the key ring is not a {@link PGPSecretKeyRing}.
     *
     * @return primary secret key or null if the key ring is public
     */
    public PGPSecretKey getSecretKey() {
        if (keys instanceof PGPSecretKeyRing) {
            PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) keys;
            return secretKeys.getSecretKey();
        }
        return null;
    }

    public PGPSecretKey getSecretKey(OpenPgpV4Fingerprint fingerprint) {
        return getSecretKey(fingerprint.getKeyId());
    }

    public PGPSecretKey getSecretKey(long keyId) {
        if (keys instanceof PGPSecretKeyRing) {
            return ((PGPSecretKeyRing) keys).getSecretKey(keyId);
        }
        return null;
    }

    /**
     * Return all secret keys of the key ring.
     * If the key ring is a {@link PGPPublicKeyRing}, then return an empty list.
     * Note that the list is unmodifiable.
     *
     * @return list of secret keys
     */
    public List<PGPSecretKey> getSecretKeys() {
        List<PGPSecretKey> list = new ArrayList<>();
        if (keys instanceof PGPSecretKeyRing) {
            PGPSecretKeyRing secretKeys = (PGPSecretKeyRing) keys;
            Iterator<PGPSecretKey> iterator = secretKeys.getSecretKeys();
            while (iterator.hasNext()) {
                list.add(iterator.next());
            }
        }
        return Collections.unmodifiableList(list);
    }

    /**
     * Return the key id of the primary key of this key ring.
     *
     * @return key id
     */
    public long getKeyId() {
        return getPublicKey().getKeyID();
    }

    /**
     * Return the {@link OpenPgpV4Fingerprint} of this key ring.
     *
     * @return fingerprint
     */
    public OpenPgpV4Fingerprint getFingerprint() {
        return new OpenPgpV4Fingerprint(getPublicKey());
    }

    /**
     * Return a list of all user-ids of the primary key.
     *
     * @return list of user-ids
     */
    public List<String> getUserIds() {
        List<String> userIds = new ArrayList<>();
        Iterator<String> iterator = getPublicKey().getUserIDs();
        while (iterator.hasNext()) {
            userIds.add(iterator.next());
        }
        return userIds;
    }

    /**
     * Return a list of all user-ids of the primary key that appear to be email-addresses.
     *
     * @return email addresses
     */
    public List<String> getEmailAddresses() {
        List<String> userIds = getUserIds();
        List<String> emails = new ArrayList<>();
        for (String userId : userIds) {
            Matcher matcher = PATTERN_EMAIL.matcher(userId);
            if (matcher.find()) {
                emails.add(matcher.group());
            }
        }
        return emails;
    }

    /**
     * Return the algorithm of the primary key.
     *
     * @return public key algorithm
     */
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.fromId(getPublicKey().getAlgorithm());
    }

    /**
     * Return the creation date of the primary key.
     *
     * @return creation date
     */
    public Date getCreationDate() {
        return getPublicKey().getCreationTime();
    }

    /**
     * Return the date on which the key ring was last modified.
     * This date corresponds to the date of the last signature that was made on this key ring by the primary key.
     *
     * @return last modification date.
     */
    public Date getLastModified() {
        Iterator<PGPSignature> signatures = getPublicKey().getSignatures();
        long last = 0L;
        while (signatures.hasNext()) {
            PGPSignature signature = signatures.next();
            if (getKeyId() != signature.getKeyID()) {
                // Throw away signatures made from others
                continue;
            }
            last = Math.max(last, signature.getCreationTime().getTime());
        }
        return new Date(last);
    }

    /**
     * Return the date on which the primary key was revoked, or null if it has not yet been revoked.
     *
     * @return revocation date or null
     */
    public Date getRevocationDate() {
        Iterator<PGPSignature> revocations = getPublicKey().getSignaturesOfType(SignatureType.KEY_REVOCATION.getCode());
        while (revocations.hasNext()) {
            PGPSignature revocation = revocations.next();
            if (getKeyId() != revocation.getKeyID()) {
                // Throw away signatures made from others
                continue;
            }
            return revocation.getCreationTime();
        }
        return null;
    }

    /**
     * Return the date of expiration of the primary key or null if the key has no expiration date.
     *
     * @return expiration date
     */
    public Date getExpirationDate() {
        return getExpirationDate(new OpenPgpV4Fingerprint(getPublicKey()));
    }

    public Date getExpirationDate(OpenPgpV4Fingerprint fingerprint) {
        long validSeconds = keys.getPublicKey(fingerprint.getKeyId()).getValidSeconds();
        if (validSeconds == 0) {
            return null;
        }
        return new Date(getCreationDate().getTime() + (1000 * validSeconds));
    }

    /**
     * Return true if the key ring is a {@link PGPSecretKeyRing}.
     * If it is a {@link PGPPublicKeyRing} return false and if it is neither, throw an {@link AssertionError}.
     *
     * @return true if the key ring is a secret key ring.
     */
    public boolean isSecretKey() {
        if (keys instanceof PGPSecretKeyRing) {
            return true;
        } else if (keys instanceof PGPPublicKeyRing) {
            return false;
        } else {
            throw new AssertionError("Expected PGPKeyRing to be either PGPPublicKeyRing or PGPSecretKeyRing, but got " + keys.getClass().getName() + " instead.");
        }
    }

    /**
     * Return true when every secret key on the key ring is not encrypted.
     * If there is at least one encrypted secret key on the ring, return false.
     * If the ring is a {@link PGPPublicKeyRing}, return true.
     *
     * @return true if all secret keys are unencrypted.
     */
    public boolean isFullyDecrypted() {
        if (isSecretKey()) {
            for (PGPSecretKey secretKey : getSecretKeys()) {
                if (secretKey.getKeyEncryptionAlgorithm() != SymmetricKeyAlgorithm.NULL.getAlgorithmId()) {
                    return false;
                }
            }
        }
        return true;
    }

    public List<PGPSignature> getSelfSignatures() {
        return getSelfSignatures(new OpenPgpV4Fingerprint(getPublicKey()));
    }

    public List<PGPSignature> getSelfSignatures(OpenPgpV4Fingerprint subkeyFingerprint) {
        return getSelfSignatures(subkeyFingerprint.getKeyId());
    }

    public List<PGPSignature> getSelfSignatures(long subkeyId) {
        PGPPublicKey publicKey = KeyRingUtils.requirePublicKeyFrom(keys, subkeyId);
        Iterator<PGPSignature> it = publicKey.getSignaturesForKeyID(subkeyId);
        List<PGPSignature> signatures = new ArrayList<>();
        while (it.hasNext()) {
            signatures.add(it.next());
        }
        sortByCreationTimeAscending(signatures);
        return signatures;
    }

    public PGPSignature getLatestValidSelfSignature() throws PGPException {
        return getLatestValidSelfSignature(new OpenPgpV4Fingerprint(getPublicKey()));
    }

    public PGPSignature getLatestValidSelfSignature(OpenPgpV4Fingerprint fingerprint) throws PGPException {
        return getLatestValidSelfSignature(fingerprint.getKeyId());
    }

    public PGPSignature getLatestValidSelfSignature(long subkeyId) throws PGPException {
        PGPPublicKey publicKey = KeyRingUtils.requirePublicKeyFrom(keys, subkeyId);
        List<PGPSignature> signatures = getSelfSignatures(subkeyId);
        return getLatestValidSignature(publicKey, signatures, keys);
    }

    public List<PGPSignature> getBindingSignatures(OpenPgpV4Fingerprint fingerprint) {
        return getBindingSignatures(fingerprint.getKeyId());
    }

    public List<PGPSignature> getBindingSignatures(long subkeyId) {
        if (subkeyId == getKeyId()) {
            return Collections.emptyList();
        }
        PGPPublicKey publicKey = KeyRingUtils.requirePublicKeyFrom(keys, subkeyId);
        return getBindingSignatures(publicKey, getKeyId());
    }

    public static List<PGPSignature> getBindingSignatures(PGPPublicKey subKey, long primaryKeyId) {
        List<PGPSignature> signatures = new ArrayList<>();
        List<PGPSignature> bindingSigs = getSignaturesOfTypes(subKey, SignatureType.SUBKEY_BINDING);
        for (PGPSignature signature : bindingSigs) {
            if (signature.getKeyID() != primaryKeyId) {
                continue;
            }
            signatures.add(signature);
        }
        return signatures;
    }

    public static List<PGPSignature> getSignaturesOfTypes(PGPPublicKey publicKey, SignatureType... types) {
        List<PGPSignature> signatures = new ArrayList<>();
        for (SignatureType type : types) {
            Iterator<?> it = publicKey.getSignaturesOfType(type.getCode());
            while (it.hasNext()) {
                Object o = it.next();
                if (o instanceof PGPSignature) {
                    signatures.add((PGPSignature) o);
                }
            }
        }
        sortByCreationTimeAscending(signatures);
        return signatures;
    }

    public PGPSignature getLatestValidBindingSignature(long subKeyID) throws PGPException {
        PGPPublicKey publicKey = KeyRingUtils.requirePublicKeyFrom(keys, subKeyID);
        List<PGPSignature> signatures = getBindingSignatures(subKeyID);
        return getLatestValidSignature(publicKey, signatures, keys);
    }

    public PGPSignature getLatestValidSelfOrBindingSignature() throws PGPException {
        return getLatestValidSelfOrBindingSignature(new OpenPgpV4Fingerprint(getPublicKey()));
    }

    public PGPSignature getLatestValidSelfOrBindingSignature(OpenPgpV4Fingerprint fingerprint) throws PGPException {
        return getLatestValidSelfOrBindingSignature(fingerprint.getKeyId());
    }

    public PGPSignature getLatestValidSelfOrBindingSignature(long subKeyId) throws PGPException {
        PGPSignature self = getLatestValidSelfSignature(subKeyId);
        PGPSignature binding = getLatestValidBindingSignature(subKeyId);
        if (self == null) {
            return binding;
        }
        if (binding == null) {
            return self;
        }
        return self.getCreationTime().after(binding.getCreationTime()) ? self : binding;
    }

    public static PGPSignature getLatestValidSignature(PGPPublicKey publicKey, List<PGPSignature> signatures, PGPKeyRing keyRing) throws PGPException {
        List<PGPSignature> valid = new ArrayList<>();
        for (PGPSignature signature : signatures) {
            long issuerID = signature.getKeyID();
            PGPPublicKey issuer = getPublicKey(keyRing, issuerID);
            if (issuer == null) {
                continue;
            }

            if (!isSignatureValid(signature, issuer, publicKey)) {
                continue;
            }

            if (isSignatureExpired(signature)) {
                continue;
            }
            valid.add(signature);
        }
        sortByCreationTimeAscending(valid);

        return valid.isEmpty() ? null : valid.get(valid.size() - 1);
    }

    public static boolean isSignatureValid(PGPSignature signature, PGPPublicKey issuer, PGPPublicKey target) throws PGPException {
        SignatureType signatureType = SignatureType.valueOf(signature.getSignatureType());
        switch (signatureType) {
            case BINARY_DOCUMENT:
            case CANONICAL_TEXT_DOCUMENT:
            case STANDALONE:
            case TIMESTAMP:
            case THIRD_PARTY_CONFIRMATION:
                throw new IllegalArgumentException("Signature is not a key signature.");
            case GENERIC_CERTIFICATION:
            case NO_CERTIFICATION:
            case CASUAL_CERTIFICATION:
            case POSITIVE_CERTIFICATION:
            case DIRECT_KEY:
            case KEY_REVOCATION:
            case CERTIFICATION_REVOCATION:
                return isSelfSignatureValid(signature, issuer);
            case SUBKEY_BINDING:
            case PRIMARYKEY_BINDING:
            case SUBKEY_REVOCATION:
                return isKeyOnKeySignatureValid(signature, issuer, target);
        }
        return false;
    }

    public static boolean isKeyOnKeySignatureValid(PGPSignature signature, PGPPublicKey issuer, PGPPublicKey target) throws PGPException {
        signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), issuer);
        return signature.verifyCertification(issuer, target);
    }

    public static boolean isSelfSignatureValid(PGPSignature signature, PGPPublicKey publicKey) throws PGPException {
        signature.init(ImplementationFactory.getInstance().getPGPContentVerifierBuilderProvider(), publicKey);
        switch (signature.getSignatureType()) {
            case PGPSignature.POSITIVE_CERTIFICATION:
            case PGPSignature.DEFAULT_CERTIFICATION:
                for (Iterator<String> it = publicKey.getUserIDs(); it.hasNext(); ) {
                    String userId = it.next();
                    boolean valid = signature.verifyCertification(userId, publicKey);
                    if (valid) {
                        return true;
                    }
                }
        }
        return false;
    }

    public static boolean isSignatureExpired(PGPSignature signature) {
        long expiration = signature.getHashedSubPackets().getSignatureExpirationTime();
        if (expiration == 0) {
            return false;
        }
        Date now = new Date();
        Date creation = signature.getCreationTime();
        return now.after(new Date(creation.getTime() + 1000 * expiration));
    }

    public static void sortByCreationTimeAscending(List<PGPSignature> signatures) {
        signatures.sort(Comparator.comparing(PGPSignature::getCreationTime));
    }
}
