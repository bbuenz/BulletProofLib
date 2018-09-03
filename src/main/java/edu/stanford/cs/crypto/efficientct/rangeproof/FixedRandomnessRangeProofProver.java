package edu.stanford.cs.crypto.efficientct.rangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.commitments.PolyCommitment;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProver;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductWitness;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Optional;
import java.util.Random;

/**
 * Created by buenz on 7/2/17.
 */
public class FixedRandomnessRangeProofProver<T extends GroupElement<T>> implements Prover<GeneratorParams<T>, T, PeddersenCommitment<T>, RangeProof<T>> {
    private final Random seededInsecureRNG;

    public FixedRandomnessRangeProofProver(long seed) {
        this.seededInsecureRNG = new Random(seed);
    }

    @Override
    public RangeProof<T> generateProof(GeneratorParams<T> parameter, T commitment, PeddersenCommitment<T> witness, Optional<BigInteger> salt) {
        BigInteger q = parameter.getGroup().groupOrder();

        BigInteger number = witness.getX();
        VectorBase<T> vectorBase = parameter.getVectorBase();
        PeddersenBase<T> base = parameter.getBase();
        int n = vectorBase.getGs().size();
        FieldVector aL = FieldVector.from(VectorX.range(0, n).map(i -> number.testBit(i) ? BigInteger.ONE : BigInteger.ZERO), q);
        FieldVector aR = aL.subtract(VectorX.fill(n, BigInteger.ONE));
        BigInteger alpha = new BigInteger(255, seededInsecureRNG);
        T a = vectorBase.commit(aL, aR, alpha);
        // FieldVector sL = FieldVector.from(VectorX.generate(n, () -> new BigInteger(255, seededInsecureRNG)), q);
        // FieldVector sR = FieldVector.from(VectorX.generate(n, () -> new BigInteger(255, seededInsecureRNG)), q);
        FieldVector sL = FieldVector.from(VectorX.generate(n, () -> BigInteger.ZERO), q);
        FieldVector sR = FieldVector.from(VectorX.generate(n, () -> BigInteger.ZERO), q);

        BigInteger rho = new BigInteger(255, seededInsecureRNG);
        T s = vectorBase.commit(sL, sR, rho);
        BigInteger y;
       if (salt.isPresent()) {
           y = ProofUtils.computeChallenge(q, salt.get(), commitment, a, s);
       } else {
           y = ProofUtils.computeChallenge(q, commitment, a, s);

       }
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, yi -> yi.multiply(y).mod(q)), q);
        System.out.println("Y2 0x" + ys.get(2).toString(16));

        //   BigInteger z = ProofUtils.challengeFromints(q, y);
        BigInteger z = BigInteger.ZERO;
        BigInteger zSquared = z.pow(2).mod(q);
        BigInteger zCubed = z.pow(3).mod(q);

        FieldVector twos = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, bi -> bi.shiftLeft(1)), q);
        FieldVector l0 = aL.add(z.negate());

        FieldVector l1 = sL;
        FieldVector twoTimesZSquared = twos.times(zSquared);
        FieldVector r0 = ys.hadamard(aR.add(z)).add(twoTimesZSquared);
        FieldVector r1 = sR.hadamard(ys);
        System.out.println("Ysum 0x" + ys.sum().mod(q).toString(16));
        BigInteger k = ys.sum().multiply(z.subtract(zSquared)).subtract(zCubed.multiply(BigInteger.ONE.shiftLeft(n).subtract(BigInteger.ONE))).mod(q);
        System.out.println("Delta 0x" + k.toString(16));
        BigInteger t0 = k.add(zSquared.multiply(number)).mod(q);
        BigInteger t1 = l1.innerPoduct(r0).add(l0.innerPoduct(r1));
        BigInteger t2 = l1.innerPoduct(r1);
        PeddersenCommitment<T> t0Commit = new PeddersenCommitment<>(base, t0, BigInteger.ZERO);
        PeddersenCommitment<T> t1Commit = new PeddersenCommitment<>(base, t1, new BigInteger(255, seededInsecureRNG));
        PeddersenCommitment<T> t2Commit = new PeddersenCommitment<>(base, t2, new BigInteger(255, seededInsecureRNG));

        VectorX<PeddersenCommitment<T>> vectorTs = VectorX.of(t0Commit, t1Commit, t2Commit);
        PolyCommitment<T> polyCommitment = new PolyCommitment<>(vectorTs);

        BigInteger x = ProofUtils.computeChallenge(q, z, polyCommitment.getCommitments());
        PeddersenCommitment<T> evalCommit = polyCommitment.evaluate(x);
        BigInteger tauX = zSquared.multiply(witness.getR()).add(evalCommit.getR()).mod(q);
        BigInteger t = evalCommit.getX();
        BigInteger mu = alpha.add(rho.multiply(x)).mod(q);

        BigInteger uChallenge = ProofUtils.challengeFromints(q, x, tauX, mu, t);
        T u = base.g.multiply(uChallenge);
        GeneratorVector<T> hs = vectorBase.getHs();
        GeneratorVector<T> gs = vectorBase.getGs();
        GeneratorVector<T> hPrimes = hs.haddamard(ys.invert());
        FieldVector l = l0.add(l1.times(x));
        FieldVector r = r0.add(r1.times(x));
        FieldVector hExp = ys.times(z).add(twoTimesZSquared);
        T P = a.add(s.multiply(x)).add(gs.sum().multiply(z.negate())).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase<T> primeBase = new VectorBase<>(gs, hPrimes, u);
        InnerProductProver<T> prover = new InnerProductProver<>();
        InnerProductWitness innerProductWitness = new InnerProductWitness(l, r);
        InnerProductProof<T> proof = prover.generateProof(primeBase, P, innerProductWitness, uChallenge);

        GeneratorVector<T> tCommits = new GeneratorVector<>(polyCommitment.getCommitments(), parameter.getGroup());
        return new RangeProof<>(a, s, tCommits, tauX, mu, t, proof);
    }
}
