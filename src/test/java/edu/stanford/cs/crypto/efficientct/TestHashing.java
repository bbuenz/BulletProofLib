package edu.stanford.cs.crypto.efficientct;

import edu.stanford.cs.crypto.efficientct.algebra.BN128Group;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;

public class TestHashing {
    @Test
    public void testSha3(){
        BigInteger output=new BigInteger("78338746147236970124700731725183845421594913511827187288591969170390706184117");
        System.out.println(output.toString(16));
        byte[] arr=new byte[32];
        Arrays.fill(arr,0,31,(byte) 0);
       BigInteger hash= ProofUtils.hash(new String(arr));

        System.out.println(hash.add(hash));
        System.out.println(hash.add(hash).mod(BN128Group.ORDER));
        System.out.println(hash.add(hash).mod(BN128Group.ORDER).toString(16));



    }
}
