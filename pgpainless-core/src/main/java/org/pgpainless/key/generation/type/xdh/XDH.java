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
package org.pgpainless.key.generation.type.xdh;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.pgpainless.algorithm.PublicKeyAlgorithm;
import org.pgpainless.key.generation.type.KeyType;

public final class XDH implements KeyType {

    private final XDHCurve curve;

    private XDH(XDHCurve curve) {
        this.curve = curve;
    }

    public static XDH fromCurve(XDHCurve curve) {
        return new XDH(curve);
    }

    @Override
    public String getName() {
        return "XDH";
    }

    @Override
    public PublicKeyAlgorithm getAlgorithm() {
        return PublicKeyAlgorithm.ECDH;
    }

    @Override
    public AlgorithmParameterSpec getAlgorithmSpec() {
        return new ECNamedCurveGenParameterSpec(curve.getName());
    }

    @Override
    public boolean canSign() {
        return false;
    }

    @Override
    public boolean canEncryptCommunication() {
        return true;
    }
}
