package edu.stanford.cs.crypto.efficientct.rangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.innerproduct.EfficientInnerProductVerifier;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by buenz on 7/1/17.
 */
public class SingleMultiExpRangeProofVerifier<T extends GroupElement<T>> implements Verifier<GeneratorParams<T>, T, RangeProof<T>> {


    @Override
    public void verify(GeneratorParams<T> params, T input, RangeProof<T> proof) throws VerificationFailedException {
        VectorBase<T> vectorBase = params.getVectorBase();
        PeddersenBase<T> base = params.getBase();
        int n = vectorBase.getGs().size();
        T a = proof.getaI();
        T s = proof.getS();

        BigInteger q = params.getGroup().groupOrder();
        BigInteger y = ProofUtils.computeChallenge(q,input, a, s);
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply),q);

        BigInteger z = ProofUtils.challengeFromints(q,y);
        BigInteger zSquared = z.pow(2).mod(q);
        BigInteger zCubed = z.pow(3).mod(q);

        FieldVector twos = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, bi -> bi.shiftLeft(1)),q);
        FieldVector twoTimesZSquared = twos.times(zSquared);
        GeneratorVector<T> tCommits = proof.gettCommits();

        BigInteger x = ProofUtils.computeChallenge(q, tCommits);

        BigInteger tauX = proof.getTauX();
        BigInteger mu = proof.getMu();
        BigInteger t = proof.getT();
        T lhs = base.commit(t, tauX);
        BigInteger k = ys.sum().multiply(z.subtract(zSquared)).subtract(zCubed.shiftLeft(n).subtract(zCubed));
        T rhs = tCommits.commit(Arrays.asList(x, x.pow(2))).add(input.multiply(zSquared)).add(base.commit(k, BigInteger.ZERO));
        equal(lhs, rhs, "Polynomial identity check failed, LHS: %s, RHS %s");

        BigInteger uChallenge = ProofUtils.challengeFromints(q,tauX, mu, t);
        T u = base.g.multiply(uChallenge);
        GeneratorVector<T> hs = vectorBase.getHs();
        GeneratorVector<T> gs = vectorBase.getGs();
        GeneratorVector<T> hPrimes = hs.haddamard(ys.invert());
        FieldVector hExp = ys.times(z).add(twoTimesZSquared);
        T P = a.add(s.multiply(x)).add(gs.sum().multiply(z.negate())).add(hPrimes.commit(hExp)).subtract(base.h.multiply(mu)).add(u.multiply(t));
        VectorBase<T> primeBase = new VectorBase<>(gs, hPrimes, u);
        InnerProductProof<T> innerProductProof=proof.getProductProof();
        List<T> ls=innerProductProof.getL();
        List<T> rs=innerProductProof.getR();
        List<BigInteger> challenges=new ArrayList<>(ls.size());
        List<BigInteger> squareChallenges=new ArrayList<>(ls.size());

        for (int i = 0; i < ls.size(); ++i) {
            T l = ls.get(i);
            T r = rs.get(i);
            BigInteger xIP = ProofUtils.computeChallenge(q, l, r);
            challenges.add(xIP);
            squareChallenges.add(xIP.modPow(BigInteger.TWO,q));


        }
        BigInteger d=challenges.stream().reduce(BigInteger.ONE,(le,ri)->le.multiply(ri).mod(q));
        BigInteger[] exponents=new BigInteger[n];
        exponents[0]=d.modInverse(q);
        for(int i=0;i<ls.size();++i){
            for(int j=0;(1<<j)+i<n;++j){
                exponents[(1<<j)+i]=exponents[0].multiply(squareChallenges.get(j)).mod(q);
            }
        }

        EfficientInnerProductVerifier<T> verifier = new EfficientInnerProductVerifier<>();
        verifier.verify(primeBase, P, proof.getProductProof());


    }
}
