package edu.stanford.cs.crypto.efficientct.rangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.commitments.PolyCommitment;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProver;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductWitness;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Optional;

/**
 * Created by buenz on 7/2/17.
 */
public class RangeProofProver<T extends GroupElement<T>> implements Prover<GeneratorParams<T>, T, PeddersenCommitment<T>, RangeProof<T>> {

    @Override
    public RangeProof<T> generateProof(GeneratorParams<T> parameter, T input, PeddersenCommitment<T> witness) {
        return generateProof(parameter, input, witness, Optional.empty());
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
        BigInteger alpha = ProofUtils.randomNumber();
        T a = vectorBase.commit(aL, aR, alpha);
        FieldVector sL = FieldVector.random(n, q);
        FieldVector sR = FieldVector.random(n, q);
        BigInteger rho = ProofUtils.randomNumber();
        T s = vectorBase.commit(sL, sR, rho);
        BigInteger y;
        if (salt.isPresent()) {
            y = ProofUtils.computeChallenge(q, salt.get(), commitment, a, s);
        } else {
            y = ProofUtils.computeChallenge(q, commitment, a, s);

        }
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply), q);
        BigInteger z = ProofUtils.challengeFromints(q, y);
        BigInteger zSquared = z.pow(2).mod(q);
        BigInteger zCubed = z.pow(3).mod(q);

        FieldVector twos = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, bi -> bi.shiftLeft(1)), q);
        FieldVector l0 = aL.add(z.negate());

        FieldVector l1 = sL;
        FieldVector twoTimesZSquared = twos.times(zSquared);
        FieldVector r0 = ys.hadamard(aR.add(z)).add(twoTimesZSquared);
        FieldVector r1 = sR.hadamard(ys);
        BigInteger k = ys.sum().multiply(z.subtract(zSquared)).subtract(zCubed.shiftLeft(n).subtract(zCubed));
        BigInteger t0 = k.add(zSquared.multiply(number)).mod(q);
        BigInteger t1 = l1.innerPoduct(r0).add(l0.innerPoduct(r1));
        BigInteger t2 = l1.innerPoduct(r1);
        PolyCommitment<T> polyCommitment = PolyCommitment.from(base, t0, VectorX.of(t1, t2));
        //TODO:Take z into the challenge
        BigInteger x = ProofUtils.computeChallenge(q,z, polyCommitment.getCommitments());

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
        InnerProductProof<T> proof = prover.generateProof(primeBase, P, innerProductWitness,uChallenge);
        System.out.println("y " +y);
        System.out.println("z " +z);

        System.out.println("x " +x);
        System.out.println("u " +uChallenge);
        T lhs = base.commit(t.subtract(k), tauX);
        System.out.println(lhs);
        T rhs = new GeneratorVector<>(polyCommitment.getCommitments(),parameter.getGroup()).commit(Arrays.asList(x, x.pow(2))).add(commitment.multiply(zSquared));
        System.out.println(rhs);
        return new RangeProof<>(a, s, new GeneratorVector<T>(polyCommitment.getCommitments(), parameter.getGroup()), tauX, mu, t, proof);
    }
}
