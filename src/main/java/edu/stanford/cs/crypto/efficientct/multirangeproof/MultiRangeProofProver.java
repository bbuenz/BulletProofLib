package edu.stanford.cs.crypto.efficientct.multirangeproof;

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
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by buenz on 7/2/17.
 */
public class MultiRangeProofProver<T extends GroupElement<T>> implements Prover<GeneratorParams<T>, GeneratorVector<T>, VectorX<PeddersenCommitment<T>>, RangeProof<T>> {


    @Override
    public RangeProof<T> generateProof(GeneratorParams<T> parameter, GeneratorVector<T> commitments, VectorX<PeddersenCommitment<T>> witness, Optional<BigInteger> salt) {
        int m = commitments.size();
        VectorBase<T> vectorBase = parameter.getVectorBase();
        PeddersenBase<T> base = parameter.getBase();
        int n = vectorBase.getGs().size();
        int bitsPerNumber = n / m;
        BigInteger q = parameter.getGroup().groupOrder();

        //Bits
        FieldVector aL = FieldVector.from(VectorX.range(0, n).map(i -> witness.get(i / bitsPerNumber).getX().testBit(i % bitsPerNumber) ? BigInteger.ONE : BigInteger.ZERO), q);
        //Bits -1
        FieldVector aR = aL.subtract(VectorX.fill(n, BigInteger.ONE));
        BigInteger alpha = ProofUtils.randomNumber();
        T a = vectorBase.commit(aL, aR, alpha);
        FieldVector sL = FieldVector.random(n, q);
        FieldVector sR = FieldVector.random(n, q);
        BigInteger rho = ProofUtils.randomNumber();
        //Blinding values
        T s = vectorBase.commit(sL, sR, rho);

        List<T> challengeArr = Stream.concat(commitments.stream(), Stream.of(a, s)).collect(Collectors.toList());
        BigInteger y;

        if(salt.isPresent()) {
             y = ProofUtils.computeChallenge(q,salt.get(), challengeArr);
        }else {
             y = ProofUtils.computeChallenge(q, challengeArr);

        }
        //y^n
        FieldVector ys = FieldVector.pow(y, n, q);

        BigInteger z = ProofUtils.challengeFromints(q, y);

        //z^Q
        FieldVector zs = FieldVector.from(VectorX.iterate(m, z.pow(2), z::multiply).map(bi -> bi.mod(q)), q);
        //2^n
        VectorX<BigInteger> twoVector = VectorX.iterate(bitsPerNumber, BigInteger.ONE, bi -> bi.shiftLeft(1));
        FieldVector twos = FieldVector.from(twoVector, q);
        //2^n \cdot z^2 || 2^n \cdot z^3 ...
        FieldVector twoTimesZs = FieldVector.from(zs.getVector().flatMap(twos::times), q);
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
        PolyCommitment<T> polyCommitment = PolyCommitment.from(base, tPolyCoefficients[0], VectorX.of(tPolyCoefficients).skip(1));
        BigInteger x = ProofUtils.computeChallenge(q,z, polyCommitment.getCommitments());
        PeddersenCommitment mainCommitment = polyCommitment.evaluate(x);

        BigInteger mu = alpha.add(rho.multiply(x)).mod(q);

        BigInteger t = mainCommitment.getX();
        BigInteger tauX = mainCommitment.getR().add(zs.innerPoduct(witness.map(PeddersenCommitment::getR)));

        BigInteger uChallenge = ProofUtils.challengeFromints(q, x, tauX, mu, t);
        T u = base.g.multiply(uChallenge);
        GeneratorVector<T> hs = vectorBase.getHs();
        GeneratorVector<T> gs = vectorBase.getGs();
        GeneratorVector<T> hPrimes = hs.haddamard(ys.invert());
        FieldVector l = lPoly.evaluate(x);
        FieldVector r = rPoly.evaluate(x);
        FieldVector hExp = ys.times(z).add(twoTimesZs);
        T P = a.add(s.multiply(x)).add(gs.sum().multiply(z.negate())).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase<T> primeBase = new VectorBase<>(gs, hPrimes, u);

        InnerProductProver<T> prover = new InnerProductProver<>();
        InnerProductWitness innerProductWitness = new InnerProductWitness(l, r);
        InnerProductProof<T> proof = prover.generateProof(primeBase, P, innerProductWitness,uChallenge);
        return new RangeProof<>(a, s, new GeneratorVector<>(polyCommitment.getCommitments(), parameter.getGroup()), tauX, mu, t, proof);
    }
}
