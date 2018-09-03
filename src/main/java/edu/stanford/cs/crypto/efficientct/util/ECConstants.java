package edu.stanford.cs.crypto.efficientct.util;/*
 * Decompiled with CFR 0_110.
 */

import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.djb.Curve25519;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Point;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

import java.math.BigInteger;

public final class ECConstants {


    public static final ECCurve BITCOIN_CURVE;
    public static final ECPoint INFINITY;
    public static final int STANDARD_SECURITY = 256;
    public static final int CHALLENGE_LENGTH = 256;
    public static final ECPoint G;
    public static final BigInteger P;

    static {
        //BNCurve
        // P = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");
        // BITCOIN_CURVE = new ECCurve.Fp(P, BigInteger.ZERO, BigInteger.valueOf(3));
        // G = BITCOIN_CURVE.createPoint(BigInteger.ONE, BigInteger.valueOf(2));
        BITCOIN_CURVE = new SecP256K1Curve();
        G = CustomNamedCurves.getByName("secp256k1").getG();
        P = BITCOIN_CURVE.getOrder();

        INFINITY = BITCOIN_CURVE.getInfinity();
    }

    private static void initializeBNCurve() {

    }

    private ECConstants() {

    }
}

