package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductVerifier;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Created by buenz on 7/6/17.
 */
public class CircuitVerifier<T extends GroupElement<T>> implements Verifier<GeneratorParams<T>, ArithmeticCircuit<T>, CircuitProof<T>> {

    @Override
    public void verify(GeneratorParams<T> parameter, ArithmeticCircuit<T> circuit, CircuitProof<T> proof, Optional<BigInteger> salt) throws VerificationFailedException {
        int Q = circuit.getlWeights().size();
        VectorBase<T> vectorBase = parameter.getVectorBase();
        PeddersenBase<T> base = parameter.getBase();
        int n = vectorBase.getGs().size();
        BigInteger q = parameter.getGroup().groupOrder();

        T aI = proof.getaI();
        T aO = proof.getAo();
        T s = proof.getS();
        BigInteger y;
        if (salt.isPresent()) {
            y = ProofUtils.computeChallenge(q, salt.get(), aI, aO, s);
        } else {
            y = ProofUtils.computeChallenge(q, aI, aO, s);
        }
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply), q);

        BigInteger z = ProofUtils.computeChallenge(q,y);

        FieldVector zs = FieldVector.from(VectorX.iterate(Q, z, z::multiply).map(bi -> bi.mod(q)), q);
        FieldVector zRWeights = ys.invert().hadamard(zs.vectorMatrixProduct(circuit.getrWeights()));
        FieldVector zLWeights = zs.vectorMatrixProduct(circuit.getlWeights());
        FieldVector zOWeights = zs.vectorMatrixProduct(circuit.getoWeights());

        GeneratorVector<T> tCommits = proof.gettCommits();
        BigInteger x = ProofUtils.computeChallenge(q, z,tCommits);
        BigInteger k = zLWeights.innerPoduct(zRWeights);


        BigInteger tauX = proof.getTauX();
        BigInteger mu = proof.getMu();
        BigInteger t = proof.getT();
        T lhs = base.commit(t, tauX);
        BigInteger cQ = zs.innerPoduct(circuit.getCs());
        VectorX<BigInteger> xs = VectorX.iterate(4, x.pow(3), x::multiply).prepend(x);
        BigInteger xSquared = x.pow(2).mod(q);

        T vZ = circuit.getCommitments().commit(zs.vectorMatrixProduct(circuit.getCommitmentWeights()).times(xSquared));
        T rhs = tCommits.commit(xs).add(base.commit(k.add(cQ).multiply(xSquared), BigInteger.ZERO)).add(vZ);
        equal(lhs, rhs, "Polynomial identity check failed, LHS: %s, RHS %s");


        BigInteger uChallenge = ProofUtils.challengeFromints(q, x,tauX, mu, t);
        T u = base.g.multiply(uChallenge);
        GeneratorVector<T> hs = vectorBase.getHs();
        GeneratorVector<T> gs = vectorBase.getGs();
        GeneratorVector<T> hPrimes = hs.haddamard(ys.invert());
        FieldVector gExp = zRWeights.times(x);
        FieldVector hExp = zLWeights.times(x).add(zOWeights).subtract(ys);
        T P = aI.multiply(x).add(aO.multiply(xSquared)).add(s.multiply(x.pow(3))).add(gs.commit(gExp)).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase<T> primeBase = new VectorBase<>(gs, hPrimes, u);
        InnerProductVerifier<T> verifier = new InnerProductVerifier<>();
        verifier.verify(primeBase, P, proof.getProductProof(),uChallenge);

    }
}
