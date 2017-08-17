package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.*;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.commitments.PolyCommitment;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProver;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductWitness;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ECConstants;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Created by buenz on 7/6/17.
 */
public class CircuitProver implements Prover<GeneratorParams, ArithmeticCircuit, CircuitWitness, CircuitProof> {

    @Override
    public CircuitProof generateProof(GeneratorParams parameter, ArithmeticCircuit circuit, CircuitWitness witness) {
        int m = circuit.getCommitments().size();
        int q = circuit.getlWeights().size();
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
        PeddersenCommitment[] peddersenCommitments = new PeddersenCommitment[7];
        for (int i = 0; i < 7; ++i) {
            if (i == 0 || i == 2) {
                peddersenCommitments[i] = new PeddersenCommitment(base, tPoly.getCoefficients()[i], BigInteger.ZERO);
            } else {
                peddersenCommitments[i] = new PeddersenCommitment(base, tPoly.getCoefficients()[i], ProofUtils.randomNumber());
            }
        }

        PolyCommitment polyCommitment = new PolyCommitment(VectorX.of(peddersenCommitments));
        BigInteger x = ProofUtils.computeChallenge(polyCommitment.getCommitments());
        PeddersenCommitment mainCommitment = polyCommitment.evaluate(x);

        BigInteger mu = alpha.multiply(x).add(beta.multiply(x.pow(2))).add(rho.multiply(x.pow(3))).mod(p);

        BigInteger t = mainCommitment.getX();
        FieldVector commitTimesWeights = FieldVector.from(witness.getCommitments().map(PeddersenCommitment::getR)).matrixVectorProduct(circuit.getCommitmentWeights());
        BigInteger zGamma = zs.innerPoduct(commitTimesWeights);
        BigInteger tauX = mainCommitment.getR().add(x.pow(2).multiply(zGamma));


        BigInteger uChallenge = ProofUtils.challengeFromInts(tauX, mu, t);
        ECPoint u = base.g.multiply(uChallenge);
        GeneratorVector hs = vectorBase.getHs();
        GeneratorVector gs = vectorBase.getGs();
        GeneratorVector hPrimes = hs.haddamard(ys.invert());
        FieldVector l = lPoly.evaluate(x);
        FieldVector r = rPoly.evaluate(x);
        FieldVector gExp = zRWeights.times(x);
        FieldVector hExp = zLWeights.times(x).add(zOWeights).subtract(ys);
        ECPoint P = aI.multiply(x).add(aO.multiply(x.pow(2))).add(s.multiply(x.pow(3))).add(gs.commit(gExp)).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase primeBase = new VectorBase(gs, hPrimes, u);
        InnerProductProver prover = new InnerProductProver();
        InnerProductWitness innerProductWitness = new InnerProductWitness(l, r);

        InnerProductProof proof = prover.generateProof(primeBase, P, innerProductWitness);

        return new CircuitProof(aI, aO, s, GeneratorVector.from(polyCommitment.getCommitments()), tauX, mu, t, proof);

    }
}
