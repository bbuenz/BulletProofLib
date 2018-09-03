package edu.stanford.cs.crypto.efficientct.multirangeproof;

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
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by buenz on 7/1/17.
 */
public class MultiRangeProofVerifier<T extends GroupElement<T>> implements Verifier<GeneratorParams<T>, GeneratorVector<T>, RangeProof<T>> {
    @Override
    public void verify(GeneratorParams<T> params, GeneratorVector<T> commitments, RangeProof<T> proof, Optional<BigInteger> salt) throws VerificationFailedException {
        int m = commitments.size();
        VectorBase<T> vectorBase = params.getVectorBase();
        PeddersenBase<T> base = params.getBase();
        int n = vectorBase.getGs().size();
        int bitsPerNumber = n / m;

        BigInteger q = params.getGroup().groupOrder();

        T a = proof.getaI();
        T s = proof.getS();

        List<T> challengeArr = Stream.concat(commitments.stream(), Stream.of(a, s)).collect(Collectors.toList());
        BigInteger y;
        if (salt.isPresent()) {
            y = ProofUtils.computeChallenge(q, salt.get(), challengeArr);
        } else {
            y = ProofUtils.computeChallenge(q, challengeArr);

        }
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply), q);

        BigInteger z = ProofUtils.challengeFromints(q, y);
        FieldVector zs = FieldVector.from(VectorX.iterate(m, z.pow(2), z::multiply).map(bi -> bi.mod(q)), q);

        VectorX<BigInteger> twoVector = VectorX.iterate(bitsPerNumber, BigInteger.ONE, bi -> bi.shiftLeft(1));
        FieldVector twos = FieldVector.from(twoVector, q);
        FieldVector twoTimesZSquared = FieldVector.from(zs.getVector().flatMap(twos::times), q);
        BigInteger zSum = zs.sum().multiply(z).mod(q);
        BigInteger k = ys.sum().multiply(z.subtract(zs.get(0))).subtract(zSum.shiftLeft(bitsPerNumber).subtract(zSum)).mod(q);

        GeneratorVector<T> tCommits = proof.gettCommits();


        BigInteger x = ProofUtils.computeChallenge(q, z, tCommits);

        BigInteger tauX = proof.getTauX();
        BigInteger mu = proof.getMu();
        BigInteger t = proof.getT();
        T lhs = base.commit(t, tauX);
        T rhs = tCommits.commit(Arrays.asList(x, x.pow(2).mod(q))).add(commitments.commit(zs)).add(base.commit(k, BigInteger.ZERO));
        equal(lhs, rhs, "Polynomial identity check failed, LHS: %s, RHS %s");


        BigInteger uChallenge = ProofUtils.challengeFromints(q, x, tauX, mu, t);
        T u = base.g.multiply(uChallenge);
        GeneratorVector<T> hs = vectorBase.getHs();
        GeneratorVector<T> gs = vectorBase.getGs();
        GeneratorVector<T> hPrimes = hs.haddamard(ys.invert());
        FieldVector hExp = ys.times(z).add(twoTimesZSquared);
        T P = a.add(s.multiply(x)).add(gs.sum().multiply(z.negate())).add(hPrimes.commit(hExp)).add(u.multiply(t)).subtract(base.h.multiply(mu));
        VectorBase<T> primeBase = new VectorBase<>(gs, hPrimes, u);
        // System.out.println("PProof "+P.normalize());
        // System.out.println("XProof " +x);
        // System.out.println("YProof " +y);
        // System.out.println("ZProof " +z);
        // System.out.println("uProof " +u);
        InnerProductVerifier<T> verifier = new InnerProductVerifier<>();
        verifier.verify(primeBase, P, proof.getProductProof(), uChallenge);

    }
}
