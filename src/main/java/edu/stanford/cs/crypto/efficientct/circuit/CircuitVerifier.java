package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.*;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductVerifier;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Created by buenz on 7/6/17.
 */
public class CircuitVerifier implements Verifier<GeneratorParams, ArithmeticCircuit, CircuitProof> {

    @Override
    public void verify(GeneratorParams parameter, ArithmeticCircuit circuit, CircuitProof proof) throws VerificationFailedException {
        int q = circuit.getCommitments().size();
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

        GeneratorVector tCommits = proof.gettCommits();
        BigInteger x = ProofUtils.computeChallenge(tCommits);
        BigInteger k = zLWeights.innerPoduct(zRWeights);


        BigInteger tauX = proof.getTauX();
        BigInteger mu = proof.getMu();
        BigInteger t = proof.getT();
        ECPoint lhs = base.commit(t, tauX);
        ECPoint rhs = tCommits.commit(Arrays.asList(x, x.pow(2).mod(ECConstants.P))).add(tCommits.commit(zs)).add(base.commit(k, BigInteger.ZERO));
        equal(lhs, rhs, "Polynomial identity check failed, LHS: %s, RHS %s");

        ECPoint u = ProofUtils.fromSeed(ProofUtils.challengeFromInts(tauX, mu, t));
        GeneratorVector hs = vectorBase.getHs();
        GeneratorVector gs = vectorBase.getGs();
        GeneratorVector hPrimes = hs.haddamard(ys.invert());
        FieldVector gExp = ys.hadamard(circuit.getrWeights().zip(zs, FieldVector::times).reduce(FieldVector::add).get());
        FieldVector hExp = circuit.getlWeights().zip(circuit.getoWeights(),FieldVector::add).zip(zs, FieldVector::times).reduce(FieldVector::add).get();
        ECPoint P = aI.multiply(x).add(aO).add(s.multiply(x.pow(3))).add(gs.commit(gExp)).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
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
