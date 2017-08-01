package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.*;
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
 * Created by buenz on 7/6/17.
 */
public class CircuitProver implements Prover<GeneratorParams, ArithmeticCircuit, CircuitWitness, CircuitProof> {

    @Override
    public CircuitProof generateProof(GeneratorParams parameter, ArithmeticCircuit circuit, CircuitWitness witness) {
        int q = circuit.getCommitments().size();
        VectorBase vectorBase = parameter.getVectorBase();
        PeddersenBase base = parameter.getBase();
        int n = vectorBase.getGs().size();

        BigInteger alpha = ProofUtils.randomNumber();
        FieldVector aL = witness.getL();
        FieldVector aR = witness.getR();
        ECPoint aI = vectorBase.commit(aL, aR, alpha);
        BigInteger beta = ProofUtils.randomNumber();

        FieldVector o = witness.getO();
        ECPoint aO = vectorBase.commit(o, beta);
        FieldVector sL = FieldVector.random(n);
        FieldVector sR = FieldVector.random(n);
        BigInteger rho = ProofUtils.randomNumber();
        ECPoint s = vectorBase.commit(sL, sR, rho);

        BigInteger y = ProofUtils.computeChallenge(aI, aO, s);
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply));

        BigInteger z = ProofUtils.hash("z", y);

        BigInteger p = ECConstants.P;
        FieldVector zs = FieldVector.from(VectorX.iterate(q, z, z::multiply).map(bi -> bi.mod(p)));

        FieldVector zRWeights = ys.invert().hadamard(zs.vectorMatrixProduct(circuit.getrWeights()));
        FieldVector zLWeights = zs.vectorMatrixProduct(circuit.getlWeights());

        FieldVector l1 = aL.add(zRWeights);
        FieldVector l2 = o;
        FieldVector l3 = sL;
        FieldVectorPolynomial lPoly = new FieldVectorPolynomial(null, l1, l2, l3);
        FieldVector r0 = zs.vectorMatrixProduct(circuit.getoWeights()).add(ys.times(BigInteger.ONE.negate()));
        FieldVector r1 = ys.hadamard(aR).add(zLWeights);
        FieldVector r3 = sR.hadamard(ys);
        FieldVectorPolynomial rPoly = new FieldVectorPolynomial(r0, r1, null, r3);

        FieldPolynomial tPoly = lPoly.innerProduct(rPoly);

        PolyCommittment polyCommittment = PolyCommittment.from(base, VectorX.of(tPoly.getCoefficients()));
        BigInteger x = ProofUtils.computeChallenge(polyCommittment.getCommitments());
        PeddersenCommitment mainCommitment = polyCommittment.evaluate(x);

        BigInteger mu = alpha.add(rho.multiply(x)).mod(p);

        BigInteger t = mainCommitment.getX();
        BigInteger tauX = mainCommitment.getR().add(zs.innerPoduct(witness.getCommitments().map(PeddersenCommitment::getR)));

        ECPoint u = ProofUtils.fromSeed(ProofUtils.challengeFromInts(tauX, mu, t).mod(p));
        GeneratorVector hs = vectorBase.getHs();
        GeneratorVector gs = vectorBase.getGs();
        GeneratorVector hPrimes = hs.haddamard(ys.invert());
        FieldVector l = lPoly.evaluate(x);
        FieldVector r = rPoly.evaluate(x);
        FieldVector gExp = ys.hadamard(circuit.getrWeights().zip(zs, FieldVector::times).reduce(FieldVector::add).get());
        FieldVector hExp = circuit.getlWeights().zip(circuit.getoWeights(),FieldVector::add).zip(zs, FieldVector::times).reduce(FieldVector::add).get();
        ECPoint P = aI.multiply(x).add(aO).add(s.multiply(x.pow(3))).add(gs.commit(gExp)).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase primeBase = new VectorBase(gs, hPrimes, u);
        InnerProductProver prover = new InnerProductProver();
        InnerProductWitness innerProductWitness = new InnerProductWitness(l, r);
        InnerProductProof proof = prover.generateProof(primeBase, P, innerProductWitness);
        return new CircuitProof(aI,aO, s, GeneratorVector.from(polyCommittment.getCommitments()), tauX, mu, t, proof);

    }
}
