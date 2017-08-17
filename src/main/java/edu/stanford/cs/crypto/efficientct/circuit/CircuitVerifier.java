package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.*;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductVerifier;
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
public class CircuitVerifier implements Verifier<GeneratorParams, ArithmeticCircuit, CircuitProof> {

    @Override
    public void verify(GeneratorParams parameter, ArithmeticCircuit circuit, CircuitProof proof) throws VerificationFailedException {
        int m = circuit.getCommitments().size();
        int q = circuit.getlWeights().size();
        VectorBase vectorBase = parameter.getVectorBase();
        PeddersenBase base = parameter.getBase();
        int n = vectorBase.getGs().size();

        ECPoint aI = proof.getaI();

        ECPoint aO = proof.getAo();
        ECPoint s = proof.getS();

        BigInteger y = ProofUtils.computeChallenge(aI, aO, s);
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply));

        BigInteger z = ProofUtils.hash("z", y);

        BigInteger p = ECConstants.P;
        FieldVector zs = FieldVector.from(VectorX.iterate(q, z, z::multiply).map(bi -> bi.mod(p)));
        FieldVector zRWeights = ys.invert().hadamard(zs.vectorMatrixProduct(circuit.getrWeights()));
        FieldVector zLWeights = zs.vectorMatrixProduct(circuit.getlWeights());
        FieldVector zOWeights = zs.vectorMatrixProduct(circuit.getoWeights());

        GeneratorVector tCommits = proof.gettCommits();
        BigInteger x = ProofUtils.computeChallenge(tCommits);
        BigInteger k = zLWeights.innerPoduct(zRWeights);


        BigInteger tauX = proof.getTauX();
        BigInteger mu = proof.getMu();
        BigInteger t = proof.getT();
        ECPoint lhs = base.commit(t, tauX);
        BigInteger cQ = zs.innerPoduct(circuit.getCs());
        VectorX<BigInteger> xs = VectorX.iterate(4, x.pow(3), x::multiply).prepend(x);
        BigInteger xSquared = x.pow(2).mod(p);
        ECPoint vZ = circuit.getCommitments().commit(zs.vectorMatrixProduct(circuit.getCommitmentWeights()).times(xSquared));
        ECPoint rhs = tCommits.commit(xs).add(base.commit(k.add(cQ).multiply(xSquared), BigInteger.ZERO)).add(vZ);
        equal(lhs, rhs, "Polynomial identity check failed, LHS: %s, RHS %s");


        BigInteger uChallenge = ProofUtils.challengeFromInts(tauX, mu, t);
        ECPoint u = base.g.multiply(uChallenge);
        GeneratorVector hs = vectorBase.getHs();
        GeneratorVector gs = vectorBase.getGs();
        GeneratorVector hPrimes = hs.haddamard(ys.invert());
        FieldVector gExp = zRWeights.times(x);
        FieldVector hExp = zLWeights.times(x).add(zOWeights).subtract(ys);
        ECPoint P = aI.multiply(x).add(aO.multiply(xSquared)).add(s.multiply(x.pow(3))).add(gs.commit(gExp)).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase primeBase = new VectorBase(gs, hPrimes, u);
        InnerProductVerifier verifier = new InnerProductVerifier();
        verifier.verify(primeBase, P, proof.getProductProof());

    }
}
