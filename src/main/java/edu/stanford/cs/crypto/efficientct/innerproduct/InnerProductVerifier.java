package edu.stanford.cs.crypto.efficientct.innerproduct;

import cyclops.collections.mutable.ListX;
import edu.stanford.cs.crypto.efficientct.ECConstants;
import edu.stanford.cs.crypto.efficientct.ProofUtils;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * Created by buenz on 6/29/17.
 */
public class InnerProductVerifier implements Verifier<VectorBase, ECPoint, InnerProductProof> {
    @Override
    public void verify(VectorBase base, ECPoint c, InnerProductProof proof) throws VerificationFailedException {
        int n = base.getGs().size();
        GeneratorVector gs = base.getGs();
        GeneratorVector hs = base.getHs();

        for (int i = 0; i < proof.getL().size(); ++i) {
            int nPrime = n / 2;
            ECPoint L = proof.getL().get(i);
            ECPoint R = proof.getR().get(i);

            GeneratorVector gLeft = gs.subVector(0, nPrime);
            GeneratorVector gRight = gs.subVector(nPrime, nPrime * 2);

            GeneratorVector hLeft = hs.subVector(0, nPrime);
            GeneratorVector hRight = hs.subVector(nPrime, nPrime * 2);
            BigInteger x = ProofUtils.computeChallenge(L, c, R);

            BigInteger xInv = x.modInverse(ECConstants.P);
            BigInteger xSquare = x.pow(2).mod(ECConstants.P);
            BigInteger xInvSquare = xInv.pow(2).mod(ECConstants.P);
            ListX<BigInteger> xs = ListX.fill(nPrime, x);
            ListX<BigInteger> xInverse = ListX.fill(nPrime, xInv);
            GeneratorVector gPrime = gLeft.haddamard(xInverse).add(gRight.haddamard(xs));
            GeneratorVector hPrime = hLeft.haddamard(xs).add(hRight.haddamard(xInverse));
            if (n % 2 == 1) {
                gPrime = gPrime.plus(gs.get(n - 1));
                hPrime = hPrime.plus(hs.get(n - 1));

            }
            c = L.multiply(xSquare).add(R.multiply(xInvSquare)).add(c);

            gs = gPrime;
            hs = hPrime;
            n = gs.size();
        }
        equal(gs.size(), 1, "G Generator size is wrong %s should be 1");
        equal(hs.size(), 1, "H Generator size is wrong %s should be 1");

        ECPoint g = gs.get(0);
        ECPoint h = hs.get(0);
        BigInteger prod = proof.getA().multiply(proof.getB()).mod(ECConstants.P);
        ECPoint cProof = g.multiply(proof.getA()).add(h.multiply(proof.getB())).add(base.getH().multiply(prod));
        equal(c, cProof, "cTotal (%s) not equal to cProof (%s)");


    }


}
