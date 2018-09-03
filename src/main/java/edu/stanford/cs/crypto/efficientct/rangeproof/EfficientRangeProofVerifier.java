package edu.stanford.cs.crypto.efficientct.rangeproof;

import cyclops.collections.immutable.VectorX;
import cyclops.collections.mutable.ListX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.*;

/**
 * Created by buenz on 7/1/17.
 */
public class EfficientRangeProofVerifier<T extends GroupElement<T>> implements Verifier<GeneratorParams<T>, T, RangeProof<T>> {


    @Override
    public void verify(GeneratorParams<T> params, T input, RangeProof<T> proof, Optional<BigInteger> salt) throws VerificationFailedException {
        VectorBase<T> vectorBase = params.getVectorBase();
        PeddersenBase<T> base = params.getBase();
        int n = vectorBase.getGs().size();
        T a = proof.getaI();
        T s = proof.getS();

        BigInteger q = params.getGroup().groupOrder();
        BigInteger y;
        if (salt.isPresent()) {
            y = ProofUtils.computeChallenge(q, salt.get(), input, a, s);
        } else {
            y = ProofUtils.computeChallenge(q, input, a, s);

        }
        FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply), q);

        BigInteger z = ProofUtils.challengeFromints(q, y);
        BigInteger zSquared = z.pow(2).mod(q);
        BigInteger zCubed = z.pow(3).mod(q);

        GeneratorVector<T> tCommits = proof.gettCommits();

        BigInteger x = ProofUtils.computeChallenge(q, z, tCommits);

        BigInteger tauX = proof.getTauX();
        BigInteger mu = proof.getMu();
        BigInteger t = proof.getT();
        BigInteger k = ys.sum().multiply(z.subtract(zSquared)).subtract(zCubed.shiftLeft(n).subtract(zCubed));
        T lhs = base.commit(t.subtract(k), tauX);

        T rhs = tCommits.commit(Arrays.asList(x, x.pow(2))).add(input.multiply(zSquared));
        equal(lhs, rhs, "Polynomial identity check failed, LHS: %s, RHS %s");

        BigInteger uChallenge = ProofUtils.challengeFromints(q, x, tauX, mu, t);

        InnerProductProof<T> ipProof = proof.getProductProof();


        List<T> ls = ipProof.getL();
        List<T> rs = ipProof.getR();

        List<BigInteger> challenges = new ArrayList<>(ls.size());
        T c = a.add(s.multiply(x));
        BigInteger previousChallenge = uChallenge;
        for (int i = 0; i < ls.size(); ++i) {
            T l = ls.get(i);
            T r = rs.get(i);
            BigInteger xIP = ProofUtils.computeChallenge(q, previousChallenge, l, r);
            challenges.add(xIP);
            BigInteger xInvIP = xIP.modInverse(q);

            c = l.multiply(xIP.pow(2)).add(r.multiply(xInvIP.pow(2))).add(c);
            previousChallenge = xIP;
        }
        BigInteger[] gExponents = new BigInteger[n];

        gExponents[0] = challenges.stream().reduce(BigInteger.ONE, (l, r) -> l.multiply(r).mod(q)).modInverse(q);
        BitSet bitSet = new BitSet();
        Collections.reverse(challenges);
        for (int i = 0; i < n / 2; ++i) {
            for (int j = 0; (1 << j) + i < n; ++j) {

                int i1 = i + (1 << j);
                if (bitSet.get(i1)) {

                } else {
                    gExponents[i1] = gExponents[i].multiply(challenges.get(j).pow(2)).mod(q);
                    bitSet.set(i1);
                }
            }
        }
        BigInteger aIP = ipProof.getA();
        BigInteger bIP = ipProof.getB();
        BigInteger[] hExponents = new BigInteger[n];
        for (int i = 0; i < n; ++i) {
            hExponents[i] = gExponents[n - i - 1].multiply(bIP).subtract(zSquared.shiftLeft(i)).multiply(ys.get(i).modInverse(q)).subtract(z).mod(q);
        }
        for (int i = 0; i < n; ++i) {
            gExponents[i] = gExponents[i].multiply(aIP).add(z);

        }

        T ipLHS = params.getVectorBase().commit(ListX.of(gExponents), ListX.of(hExponents), mu);
        BigInteger gExponent = ipProof.getA().multiply(ipProof.getB()).subtract(t).multiply(uChallenge);
        ipLHS = ipLHS.add(params.getBase().g.multiply(gExponent));
        System.out.println("LHS IP " + ipLHS);
        equal(ipLHS, c, "IP check Range Proof");

    }
}
