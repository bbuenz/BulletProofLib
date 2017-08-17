package edu.stanford.cs.crypto.efficientct.innerproduct;

import cyclops.collections.mutable.ListX;
import edu.stanford.cs.crypto.efficientct.util.ECConstants;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * Created by buenz on 6/29/17.
 * This class provides an efficient inner product verifier by only using n group exponentations instead of n log(n). It however currently only works for {@link VectorBase}s of size 2^k for some k.
 */
public class EfficientInnerProductVerifier implements Verifier<VectorBase, ECPoint, InnerProductProof> {
   /**
   *Only works if params has size 2^k for some k.
    */
        @Override
    public void verify(VectorBase params, ECPoint c, InnerProductProof proof) throws VerificationFailedException {
        List<ECPoint> ls = proof.getL();
        List<ECPoint> rs = proof.getR();
        List<BigInteger> challenges = new ArrayList<>(ls.size());
        List<BigInteger> inverseChallenges = new ArrayList<>(ls.size());

        for (int i = 0; i < ls.size(); ++i) {
            ECPoint l = ls.get(i);
            ECPoint r = rs.get(i);
            BigInteger x = ProofUtils.computeChallenge(l, c, r);
            challenges.add(x);
            BigInteger xInv = x.modInverse(ECConstants.P);
            inverseChallenges.add(xInv);

            c = l.multiply(x.pow(2)).add(r.multiply(xInv.pow(2))).add(c);

        }
        int n = params.getGs().size();


        Function<Integer, BigInteger> computeChallenge = i -> {
            BigInteger multiplier = BigInteger.ONE;
            for (int j = 0; j < challenges.size(); ++j) {
                if ((i & (1 << j)) == 0) {
                    multiplier = multiplier.multiply(inverseChallenges.get(challenges.size() - j - 1)).mod(ECConstants.P);
                } else {
                    multiplier = multiplier.multiply(challenges.get(challenges.size() - j - 1)).mod(ECConstants.P);
                }
            }
            return multiplier;
        };
        ListX<BigInteger> challengeVector = ListX.range(0, n).map(computeChallenge);
        ECPoint g = params.getGs().commit(challengeVector);
        ECPoint h = params.getHs().commit(challengeVector.reverse());
        BigInteger prod = proof.getA().multiply(proof.getB()).mod(ECConstants.P);
        ECPoint cProof = g.multiply(proof.getA()).add(h.multiply(proof.getB())).add(params.getH().multiply(prod));
        equal(c, cProof, "cTotal (%s) not equal to cProof (%s)");
    }
}
