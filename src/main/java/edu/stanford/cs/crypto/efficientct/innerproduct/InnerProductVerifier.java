package edu.stanford.cs.crypto.efficientct.innerproduct;

import cyclops.collections.mutable.ListX;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Created by buenz on 6/29/17.
 */
public class InnerProductVerifier<T extends GroupElement<T>> implements Verifier<VectorBase<T>, T, InnerProductProof<T>> {
    @Override
    public void verify(VectorBase<T> base, T c, InnerProductProof<T> proof, Optional<BigInteger> salt) throws VerificationFailedException {
        int n = base.getGs().size();
        GeneratorVector<T> gs = base.getGs();
        GeneratorVector<T> hs = base.getHs();
        BigInteger q = gs.getGroup().groupOrder();
        BigInteger previousChallenge=salt.orElse(BigInteger.ZERO);
        for (int i = 0; i < proof.getL().size(); ++i) {
            int nPrime = n / 2;
            T L = proof.getL().get(i);
            T R = proof.getR().get(i);

            GeneratorVector<T> gLeft = gs.subVector(0, nPrime);
            GeneratorVector<T> gRight = gs.subVector(nPrime, nPrime * 2);

            GeneratorVector<T> hLeft = hs.subVector(0, nPrime);
            GeneratorVector<T> hRight = hs.subVector(nPrime, nPrime * 2);
            BigInteger x = ProofUtils.computeChallenge(q,previousChallenge, L, R);

            BigInteger xInv = x.modInverse(q);
            BigInteger xSquare = x.pow(2).mod(q);
            BigInteger xInvSquare = xInv.pow(2).mod(q);
            ListX<BigInteger> xs = ListX.fill(nPrime, x);
            ListX<BigInteger> xInverse = ListX.fill(nPrime, xInv);
            GeneratorVector<T> gPrime = gLeft.haddamard(xInverse).add(gRight.haddamard(xs));
            GeneratorVector<T> hPrime = hLeft.haddamard(xs).add(hRight.haddamard(xInverse));
            if (n % 2 == 1) {
                gPrime = gPrime.plus(gs.get(n - 1));
                hPrime = hPrime.plus(hs.get(n - 1));

            }
            c = L.multiply(xSquare).add(R.multiply(xInvSquare)).add(c);
            gs = gPrime;
            hs = hPrime;
            n = gs.size();
            previousChallenge=x;
        }
        equal(gs.size(), 1, "G Generator size is wrong %s should be 1");
        equal(hs.size(), 1, "H Generator size is wrong %s should be 1");

        T g = gs.get(0);
        T h = hs.get(0);
        BigInteger prod = proof.getA().multiply(proof.getB()).mod(q);
        T cProof = g.multiply(proof.getA()).add(h.multiply(proof.getB())).add(base.getH().multiply(prod));
        equal(c, cProof, "cTotal (%s) not equal to cProof (%s)");


    }


}
