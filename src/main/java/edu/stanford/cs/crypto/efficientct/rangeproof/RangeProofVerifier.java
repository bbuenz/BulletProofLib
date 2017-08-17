package edu.stanford.cs.crypto.efficientct.rangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.*;
import edu.stanford.cs.crypto.efficientct.innerproduct.EfficientInnerProductVerifier;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ECConstants;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Created by buenz on 7/1/17.
 */
public class RangeProofVerifier implements Verifier<GeneratorParams, ECPoint, RangeProof> {


    @Override
    public void verify(GeneratorParams params, ECPoint input, RangeProof proof) throws VerificationFailedException {
        VectorBase vectorBase = params.getVectorBase();
        PeddersenBase base = params.getBase();
        int n = vectorBase.getGs().size();
        ECPoint a = proof.getaI();
        ECPoint s = proof.getS();

        BigInteger y = ProofUtils.computeChallenge(input, a, s);
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply));

        BigInteger p = ECConstants.P;
        BigInteger z = ProofUtils.challengeFromInts(y);
        BigInteger zSquared = z.pow(2).mod(p);
        BigInteger zCubed = z.pow(3).mod(p);

        FieldVector twos = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, bi -> bi.shiftLeft(1)));
        FieldVector twoTimesZSquared = twos.times(zSquared);
        GeneratorVector tCommits = proof.gettCommits();

        BigInteger x = ProofUtils.computeChallenge(tCommits);

        BigInteger tauX = proof.getTauX();
        BigInteger mu = proof.getMu();
        BigInteger t = proof.getT();
        ECPoint lhs = base.commit(t, tauX);
        BigInteger k = ys.sum().multiply(z.subtract(zSquared)).subtract(zCubed.shiftLeft(n).subtract(zCubed));
        ECPoint rhs = tCommits.commit(Arrays.asList(x, x.pow(2))).add(input.multiply(zSquared)).add(base.commit(k, BigInteger.ZERO));
        equal(lhs, rhs, "Polynomial identity check failed, LHS: %s, RHS %s");

        BigInteger uChallenge = ProofUtils.challengeFromInts(tauX, mu, t);
        ECPoint u = base.g.multiply(uChallenge);
        GeneratorVector hs = vectorBase.getHs();
        GeneratorVector gs = vectorBase.getGs();
        GeneratorVector hPrimes = hs.haddamard(ys.invert());
        FieldVector hExp = ys.times(z).add(twoTimesZSquared);
        ECPoint P = a.add(s.multiply(x)).add(gs.sum().multiply(z.negate())).add(hPrimes.commit(hExp)).subtract(base.h.multiply(mu)).add(u.multiply(t));
        VectorBase primeBase = new VectorBase(gs, hPrimes, u);
        // System.out.println("PVerify "+P.normalize());
        // System.out.println("XVerify" +x);
        // System.out.println("YVerify" +y);
        // System.out.println("ZVerify" +z);
        // System.out.println("uVerify" +u);
        EfficientInnerProductVerifier verifier = new EfficientInnerProductVerifier();
        verifier.verify(primeBase, P, proof.getProductProof());

    }
}
