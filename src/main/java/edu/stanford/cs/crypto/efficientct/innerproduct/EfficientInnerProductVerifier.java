package edu.stanford.cs.crypto.efficientct.innerproduct;

import cyclops.collections.mutable.ListX;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Function;

/**
 * Created by buenz on 6/29/17.
 * This class provides an efficient inner product verifier by only using n group exponentations instead of n log(n). It however currently only works for {@link VectorBase}s of size 2^k for some k.
 */
public class EfficientInnerProductVerifier<T extends GroupElement<T>> implements Verifier<VectorBase<T>, T, InnerProductProof<T>> {
    /**
     * Only works if params has size 2^k for some k.
     */
    @Override
    public void verify(VectorBase<T> params, T c, InnerProductProof<T> proof) throws VerificationFailedException {
        List<T> ls = proof.getL();
        List<T> rs = proof.getR();
        List<BigInteger> challenges = new ArrayList<>(ls.size());
        List<BigInteger> inverseChallenges = new ArrayList<>(ls.size());
        BigInteger q = params.getGs().getGroup().groupOrder();
        for (int i = 0; i < ls.size(); ++i) {
            T l = ls.get(i);
            T r = rs.get(i);
            BigInteger x = ProofUtils.computeChallenge(q, l, c, r);
            challenges.add(x);
            BigInteger xInv = x.modInverse(q);
            inverseChallenges.add(xInv);

            c = l.multiply(x.pow(2)).add(r.multiply(xInv.pow(2))).add(c);

        }
        int n = params.getGs().size();
        BigInteger[] otherExponents = new BigInteger[n];

        otherExponents[0] = challenges.stream().reduce(BigInteger.ONE, (l, r) -> l.multiply(r).mod(q)).modInverse(q);
        BitSet bitSet = new BitSet();
        Collections.reverse(challenges);
        for (int i = 0; i < n/2; ++i) {
            for (int j = 0; (1 << j) + i < n; ++j) {

                int i1 = i + (1 << j);
                if (bitSet.get(i1)) {

                } else {
                    otherExponents[i1] = otherExponents[i].multiply(challenges.get(j).pow(2)).mod(q);
                    bitSet.set(i1);
                }
            }
        }


        ListX<BigInteger> challengeVector = ListX.of(otherExponents);
        T g = params.getGs().commit(challengeVector);
        T h = params.getHs().commit(challengeVector.reverse());
        BigInteger prod = proof.getA().multiply(proof.getB()).mod(q);
        T cProof = g.multiply(proof.getA()).add(h.multiply(proof.getB())).add(params.getH().multiply(prod));
        equal(c, cProof, "cTotal (%s) not equal to cProof (%s)");
    }
}
