package edu.stanford.cs.crypto.efficientct.innerproduct;

import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.algebra.C0C0Group;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.junit.Test;

import java.math.BigInteger;
import java.util.stream.Collectors;

public class C0C0InnerProduct {
    @Test
    public void createInnerProductProof() throws VerificationFailedException {
        InnerProductProofSystem<BouncyCastleECPoint> system = new InnerProductProofSystem<>();
        C0C0Group group = new C0C0Group();
        VectorBase<BouncyCastleECPoint> base = system.generatePublicParams(256, group);
        base.getGs().getVector().map(group::toMontgomery).map(s -> "=" + s  ).zipWithIndex().map(t -> "garr[" + t.v2 + "]" + t.v1).printOut();
        base.getHs().getVector().map(group::toMontgomery).map(s -> "=" + s ).zipWithIndex().map(t -> "harr[" + t.v2 + "]" + t.v1).printOut();
        System.out.println("u=" + group.toMontgomery(base.getH()));
        FieldVector as = FieldVector.pow(BigInteger.valueOf(2), 256, group.groupOrder());
        //  System.out.println(as);
        FieldVector bs = FieldVector.pow(BigInteger.ONE, 256, group.groupOrder());
        //  System.out.println(bs);
        InnerProductWitness witness = new InnerProductWitness(as, bs);
        BouncyCastleECPoint point = base.commit(as, bs, as.innerPoduct(bs));
        System.out.println("inner product"+as.innerPoduct(bs));
        System.out.println("P=" + group.toMontgomery(point));
        BouncyCastleECPoint.addCount = 0;
        BouncyCastleECPoint.expCount = 0;
        InnerProductProof<BouncyCastleECPoint> productProof = system.getProver().generateProof(base, point, witness);
        System.out.println(productProof.getL().size());
        String lstring = "ls=[" + productProof.getL().stream().map(group::toMontgomery).collect(Collectors.joining(",")) + "]";
        System.out.println(lstring);
        String rstring = "rs=[" + productProof.getR().stream().map(group::toMontgomery).collect(Collectors.joining(",")) + "]";
        System.out.println(rstring);
        System.out.println("a=0x" + productProof.getA().toString(16));
        System.out.println("b=0x" + productProof.getB().toString(16));
        system.getVerifier().verify(base,point,productProof);
    }
}
