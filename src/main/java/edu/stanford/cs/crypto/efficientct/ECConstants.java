package edu.stanford.cs.crypto.efficientct;/*
 * Decompiled with CFR 0_110.
 */

import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

import java.math.BigInteger;

public final class ECConstants {



    public static final ECCurve BITCOIN_CURVE = new SecP256K1Curve();
    public static final ECPoint INFINITY = BITCOIN_CURVE.getInfinity();
    public static final int STANDARD_SECURITY = 256;
    public static final int CHALLENGE_LENGTH = 256;
    public static final ECPoint G = CustomNamedCurves.getByName("secp256k1").getG();
    public static final BigInteger P = BITCOIN_CURVE.getOrder();
    public static final BigInteger CHALLENGE_Q = P.min(BigInteger.ONE.shiftLeft(256));

    private ECConstants() {
    }
}

