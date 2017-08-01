package edu.stanford.cs.crypto.efficientct.rangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.ECConstants;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.ProofUtils;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.commitments.PolyCommittment;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProver;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductWitness;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Created by buenz on 7/2/17.
 */
public class RangeProofProver implements Prover<GeneratorParams, ECPoint, RangeProofWitness, RangeProof> {


    @Override
    public RangeProof generateProof(GeneratorParams parameter, ECPoint commitment, RangeProofWitness witness) {
        BigInteger number = witness.getNumber();
        VectorBase vectorBase = parameter.getVectorBase();
        PeddersenBase base = parameter.getBase();
        int n = vectorBase.getGs().size();
        FieldVector aL = FieldVector.from(VectorX.range(0, n).map(i -> number.testBit(i) ? BigInteger.ONE : BigInteger.ZERO));
        FieldVector aR = aL.subtract(VectorX.fill(n, BigInteger.ONE));
        BigInteger alpha = ProofUtils.randomNumber();
        ECPoint a = vectorBase.commit(aL, aR, alpha);
        FieldVector sL = FieldVector.random(n);
        FieldVector sR = FieldVector.random(n);
        BigInteger rho = ProofUtils.randomNumber();
        ECPoint s = vectorBase.commit(sL, sR, rho);

        BigInteger y = ProofUtils.computeChallenge(commitment, a, s);
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply));

        BigInteger p = ECConstants.P;
        BigInteger z = ProofUtils.challengeFromInts(y);
        BigInteger zSquared = z.pow(2).mod(p);
        BigInteger zCubed = z.pow(3).mod(p);

        FieldVector twos = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, bi -> bi.shiftLeft(1)));
        FieldVector l0 = aL.add(z.negate());

        FieldVector l1 = sL;
        FieldVector twoTimesZSquared = twos.times(zSquared);
        FieldVector r0 = ys.hadamard(aR.add(z)).add(twoTimesZSquared);
        FieldVector r1 = sR.hadamard(ys);
        BigInteger k = ys.sum().multiply(z.subtract(zSquared)).subtract(zCubed.shiftLeft(n).subtract(zCubed));
        BigInteger t0 = k.add(zSquared.multiply(number));
        BigInteger t1 = l1.innerPoduct(r0).add(l0.innerPoduct(r1));
        BigInteger t2 = l1.innerPoduct(r1);
        PolyCommittment polyCommittment = PolyCommittment.from(base, VectorX.of(t0, t1, t2));

        BigInteger x = ProofUtils.computeChallenge(polyCommittment.getCommitments());

        PeddersenCommitment evalCommit = polyCommittment.evaluate(x);
        BigInteger tauX = zSquared.multiply(witness.getRandomness()).add(evalCommit.getR());
        BigInteger t = evalCommit.getX();
        BigInteger mu = alpha.add(rho.multiply(x)).mod(p);

        ECPoint u = ProofUtils.fromSeed(ProofUtils.challengeFromInts(tauX, mu, t));
        GeneratorVector hs = vectorBase.getHs();
        GeneratorVector gs = vectorBase.getGs();
        GeneratorVector hPrimes = hs.haddamard(ys.invert());
        FieldVector l = l0.add(l1.times(x));
        FieldVector r = r0.add(r1.times(x));
        FieldVector hExp = ys.times(z).add(twoTimesZSquared);
        ECPoint P = a.add(s.multiply(x)).add(gs.sum().multiply(z.negate())).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase primeBase = new VectorBase(gs, hPrimes, u);
        InnerProductProver prover = new InnerProductProver();
        InnerProductWitness innerProductWitness = new InnerProductWitness(l, r);
        InnerProductProof proof = prover.generateProof(primeBase, P, innerProductWitness);
        return new RangeProof(a, s, GeneratorVector.from(polyCommittment.getCommitments()), tauX, mu, t, proof);
    }
}
