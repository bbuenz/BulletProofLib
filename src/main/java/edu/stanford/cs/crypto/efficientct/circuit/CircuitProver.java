package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.FieldPolynomial;
import edu.stanford.cs.crypto.efficientct.FieldVectorPolynomial;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Created by buenz on 7/6/17.
 */
public class CircuitProver<T extends GroupElement<T>> implements Prover<GeneratorParams<T>, ArithmeticCircuit<T>, CircuitWitness<T>, CircuitProof<T>> {

    @Override
    public CircuitProof<T> generateProof(GeneratorParams<T> parameter, ArithmeticCircuit<T> circuit, CircuitWitness<T> witness, Optional<BigInteger> salt) {
        int Q = circuit.getlWeights().size();
        BigInteger q = parameter.getGroup().groupOrder();

        VectorBase<T> vectorBase = parameter.getVectorBase();
        PeddersenBase<T> base = parameter.getBase();
        int n = vectorBase.getGs().size();

        BigInteger alpha = ProofUtils.randomNumber();
        FieldVector aL = witness.getL();
        FieldVector aR = witness.getR();
        T aI = vectorBase.commit(aL, aR, alpha);
        BigInteger beta = ProofUtils.randomNumber();

        FieldVector o = witness.getO();
        T aO = vectorBase.commit(o, beta);

        FieldVector sL = FieldVector.random(n, q);
        FieldVector sR = FieldVector.random(n, q);
        BigInteger rho = ProofUtils.randomNumber();
        T s = vectorBase.commit(sL, sR, rho);
        BigInteger y;

        if (salt.isPresent()) {
            y = ProofUtils.computeChallenge(q, salt.get(), aI, aO, s);
        } else {
            y = ProofUtils.computeChallenge(q, aI, aO, s);

        }
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply), q);

        BigInteger z = ProofUtils.computeChallenge(q,y);

        FieldVector zs = FieldVector.from(VectorX.iterate(Q, z, z::multiply).map(bi -> bi.mod(q)), q);

        FieldVector zTimesR = zs.vectorMatrixProduct(circuit.getrWeights());
        FieldVector zRWeights = ys.invert().hadamard(zTimesR);
        FieldVector zLWeights = zs.vectorMatrixProduct(circuit.getlWeights());
        FieldVector zOWeights = zs.vectorMatrixProduct(circuit.getoWeights());

        FieldVector l1 = aL.add(zRWeights);
        FieldVector l2 = o;
        FieldVector l3 = sL;
        FieldVectorPolynomial lPoly = new FieldVectorPolynomial(null, l1, l2, l3);
        FieldVector r0 = zs.vectorMatrixProduct(circuit.getoWeights()).add(ys.times(BigInteger.ONE.negate()));
        FieldVector r1 = ys.hadamard(aR).add(zLWeights);
        FieldVector r3 = sR.hadamard(ys);
        FieldVectorPolynomial rPoly = new FieldVectorPolynomial(r0, r1, null, r3);

        FieldPolynomial tPoly = lPoly.innerProduct(rPoly);
        List<PeddersenCommitment<T>> peddersenCommitments = new ArrayList<>();
        for (int i = 0; i < 7; ++i) {
            if (i == 0 || i == 2) {
                peddersenCommitments.add(new PeddersenCommitment<>(base, tPoly.getCoefficients()[i], BigInteger.ZERO));
            } else {
                peddersenCommitments.add(new PeddersenCommitment<>(base, tPoly.getCoefficients()[i], ProofUtils.randomNumber()));
            }
        }

        PolyCommitment<T> polyCommitment = new PolyCommitment<>(VectorX.fromIterable(peddersenCommitments));
        BigInteger x = ProofUtils.computeChallenge(q, z, polyCommitment.getCommitments());
        PeddersenCommitment mainCommitment = polyCommitment.evaluate(x);

        BigInteger mu = alpha.multiply(x).add(beta.multiply(x.pow(2))).add(rho.multiply(x.pow(3))).mod(q);
        BigInteger t = mainCommitment.getX();
        FieldVector commitTimesWeights = FieldVector.from(witness.getCommitments().map(PeddersenCommitment::getR), q).matrixVectorProduct(circuit.getCommitmentWeights());
        BigInteger zGamma = zs.innerPoduct(commitTimesWeights);
        BigInteger tauX = mainCommitment.getR().add(x.pow(2).multiply(zGamma));


        BigInteger uChallenge = ProofUtils.challengeFromints(q, x, tauX, mu, t);
        T u = base.g.multiply(uChallenge);
        GeneratorVector<T> hs = vectorBase.getHs();
        GeneratorVector<T> gs = vectorBase.getGs();
        GeneratorVector<T> hPrimes = hs.haddamard(ys.invert());
        FieldVector l = lPoly.evaluate(x);
        FieldVector r = rPoly.evaluate(x);
        FieldVector gExp = zRWeights.times(x);
        FieldVector hExp = zLWeights.times(x).add(zOWeights).subtract(ys);
        T P = aI.multiply(x).add(aO.multiply(x.pow(2))).add(s.multiply(x.pow(3))).add(gs.commit(gExp)).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase<T> primeBase = new VectorBase<>(gs, hPrimes, u);
        InnerProductProver<T> prover = new InnerProductProver<>();
        InnerProductWitness innerProductWitness = new InnerProductWitness(l, r);

        InnerProductProof<T> proof = prover.generateProof(primeBase, P, innerProductWitness, uChallenge);

        return new CircuitProof<>(aI, aO, s, new GeneratorVector<>(polyCommitment.getCommitments(), parameter.getGroup()), tauX, mu, t, proof);

    }
}
