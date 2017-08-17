package edu.stanford.cs.crypto.efficientct.multirangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.*;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductVerifier;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import edu.stanford.cs.crypto.efficientct.util.ECConstants;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.stream.Stream;

/**
 * Created by buenz on 7/1/17.
 */
public class MultiRangeProofVerifier implements Verifier<GeneratorParams, GeneratorVector, RangeProof> {
    @Override
    public void verify(GeneratorParams params, GeneratorVector commitments, RangeProof proof) throws VerificationFailedException {
        int m = commitments.size();
        VectorBase vectorBase = params.getVectorBase();
        PeddersenBase base = params.getBase();
        int n = vectorBase.getGs().size();
        int bitsPerNumber = n / m;

        ECPoint a = proof.getaI();
        ECPoint s = proof.getS();

        ECPoint[] challengeArr = Stream.concat(commitments.stream(), Stream.of(a, s)).toArray(ECPoint[]::new);
        BigInteger y = ProofUtils.computeChallenge(challengeArr);
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply));

        BigInteger p = ECConstants.P;
        BigInteger z = ProofUtils.challengeFromInts(y);
        FieldVector zs = FieldVector.from(VectorX.iterate(m, z.pow(2), z::multiply).map(bi -> bi.mod(p)));

        VectorX<BigInteger> twoVector = VectorX.iterate(bitsPerNumber, BigInteger.ONE, bi -> bi.shiftLeft(1));
        FieldVector twos = FieldVector.from(twoVector);
        FieldVector twoTimesZSquared = FieldVector.from(zs.getVector().flatMap(twos::times));
        BigInteger zSum = zs.sum().multiply(z).mod(p);
        BigInteger k = ys.sum().multiply(z.subtract(zs.get(0))).subtract(zSum.shiftLeft(bitsPerNumber).subtract(zSum)).mod(ECConstants.P);

        GeneratorVector tCommits = proof.gettCommits();


        BigInteger x = ProofUtils.computeChallenge(tCommits);

        BigInteger tauX = proof.getTauX();
        BigInteger mu = proof.getMu();
        BigInteger t = proof.getT();
        ECPoint lhs = base.commit(t, tauX);
        ECPoint rhs = tCommits.commit(Arrays.asList(x, x.pow(2).mod(ECConstants.P))).add(commitments.commit(zs)).add(base.commit(k, BigInteger.ZERO));
        equal(lhs, rhs, "Polynomial identity check failed, LHS: %s, RHS %s");


        BigInteger uChallenge = ProofUtils.challengeFromInts(tauX, mu, t);
        ECPoint u = base.g.multiply(uChallenge);        GeneratorVector hs = vectorBase.getHs();
        GeneratorVector gs = vectorBase.getGs();
        GeneratorVector hPrimes = hs.haddamard(ys.invert());
        FieldVector hExp = ys.times(z).add(twoTimesZSquared);
        ECPoint P = a.add(s.multiply(x)).add(gs.sum().multiply(z.negate())).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase primeBase = new VectorBase(gs, hPrimes, u);
        // System.out.println("PProof "+P.normalize());
        // System.out.println("XProof " +x);
        // System.out.println("YProof " +y);
        // System.out.println("ZProof " +z);
        // System.out.println("uProof " +u);
        InnerProductVerifier verifier = new InnerProductVerifier();
        verifier.verify(primeBase, P, proof.getProductProof());

    }
}
