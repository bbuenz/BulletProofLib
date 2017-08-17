package edu.stanford.cs.crypto.efficientct.multirangeproof;

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
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import edu.stanford.cs.crypto.efficientct.util.ECConstants;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.stream.Stream;

/**
 * Created by buenz on 7/2/17.
 */
public class MultiRangeProofProver implements Prover<GeneratorParams, GeneratorVector, VectorX<PeddersenCommitment>, RangeProof> {


    @Override
    public RangeProof generateProof(GeneratorParams parameter, GeneratorVector commitments, VectorX<PeddersenCommitment> witness) {
        int m = commitments.size();
        VectorBase vectorBase = parameter.getVectorBase();
        PeddersenBase base = parameter.getBase();
        int n = vectorBase.getGs().size();
        int bitsPerNumber = n / m;
        //Bits
        FieldVector aL = FieldVector.from(VectorX.range(0, n).map(i -> witness.get(i / bitsPerNumber).getX().testBit(i % bitsPerNumber) ? BigInteger.ONE : BigInteger.ZERO));
        //Bits -1
        FieldVector aR = aL.subtract(VectorX.fill(n, BigInteger.ONE));
        BigInteger alpha = ProofUtils.randomNumber();
        ECPoint a = vectorBase.commit(aL, aR, alpha);
        FieldVector sL = FieldVector.random(n);
        FieldVector sR = FieldVector.random(n);
        BigInteger rho = ProofUtils.randomNumber();
        //Blinding values
        ECPoint s = vectorBase.commit(sL, sR, rho);

        ECPoint[] challengeArr = Stream.concat(commitments.stream(), Stream.of(a, s)).toArray(ECPoint[]::new);
        BigInteger y = ProofUtils.computeChallenge(challengeArr);
        //y^n
        FieldVector ys = FieldVector.pow(y, n);

        BigInteger z = ProofUtils.challengeFromInts(y);

        BigInteger p = ECConstants.P;
        //z^Q
        FieldVector zs = FieldVector.from(VectorX.iterate(m, z.pow(2), z::multiply).map(bi -> bi.mod(p)));
        //2^n
        VectorX<BigInteger> twoVector = VectorX.iterate(bitsPerNumber, BigInteger.ONE, bi -> bi.shiftLeft(1));
        FieldVector twos = FieldVector.from(twoVector);
        //2^n \cdot z || 2^n \cdot z^2 ...
        FieldVector twoTimesZs = FieldVector.from(zs.getVector().flatMap(twos::times));
        //l(X)
        FieldVector l0 = aL.add(z.negate());
        FieldVector l1 = sL;
        FieldVectorPolynomial lPoly = new FieldVectorPolynomial(l0, l1);
        //r(X)
        FieldVector r0 = ys.hadamard(aR.add(z)).add(twoTimesZs);
        FieldVector r1 = sR.hadamard(ys);
        FieldVectorPolynomial rPoly = new FieldVectorPolynomial(r0, r1);

        //t(X)
        FieldPolynomial tPoly = lPoly.innerProduct(rPoly);
        //Commit(t)
        BigInteger[] tPolyCoefficients = tPoly.getCoefficients();
        PolyCommitment polyCommitment = PolyCommitment.from(base, tPolyCoefficients[0], VectorX.of(tPolyCoefficients).skip(1));
        BigInteger x = ProofUtils.computeChallenge(polyCommitment.getCommitments());
        PeddersenCommitment mainCommitment = polyCommitment.evaluate(x);

        BigInteger mu = alpha.add(rho.multiply(x)).mod(p);

        BigInteger t = mainCommitment.getX();
        BigInteger tauX = mainCommitment.getR().add(zs.innerPoduct(witness.map(PeddersenCommitment::getR)));

        BigInteger uChallenge = ProofUtils.challengeFromInts(tauX, mu, t);
        ECPoint u = base.g.multiply(uChallenge);
        GeneratorVector hs = vectorBase.getHs();
        GeneratorVector gs = vectorBase.getGs();
        GeneratorVector hPrimes = hs.haddamard(ys.invert());
        FieldVector l = lPoly.evaluate(x);
        FieldVector r = rPoly.evaluate(x);
        FieldVector hExp = ys.times(z).add(twoTimesZs);
        ECPoint P = a.add(s.multiply(x)).add(gs.sum().multiply(z.negate())).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase primeBase = new VectorBase(gs, hPrimes, u);

        InnerProductProver prover = new InnerProductProver();
        InnerProductWitness innerProductWitness = new InnerProductWitness(l, r);
        InnerProductProof proof = prover.generateProof(primeBase, P, innerProductWitness);
        return new RangeProof(a, s, GeneratorVector.from(polyCommitment.getCommitments()), tauX, mu, t, proof);
    }
}
