/*
 * Copyright (c) 2014, Oracle America, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * Neither the name of Oracle nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

package edu.stanford.cs.crypto;

import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.innerproduct.*;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.bouncycastle.math.ec.ECPoint;
import org.openjdk.jmh.annotations.*;

@State(Scope.Benchmark)
public class InnerProductBenchmark {
    private final InnerProductProofSystem rangeProofSystem = new InnerProductProofSystem();
    private final InnerProductProver prover = new InnerProductProver();
    private final VectorBase generatorParams = rangeProofSystem.generatePublicParams(1024);
    private ECPoint commitment;
    private InnerProductWitness witness;
    private InnerProductProof oneProof;
    private EfficientInnerProductVerifier verifier1 = new EfficientInnerProductVerifier();
    private InnerProductVerifier verifier2 = new InnerProductVerifier();

    @Setup
    public void setUp() {
        FieldVector as = FieldVector.random(1024);
        FieldVector bs = FieldVector.random(1024);
        witness = new InnerProductWitness(as, bs);
        commitment = generatorParams.commit(as, bs, as.innerPoduct(bs));
        oneProof = testProving();
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    public InnerProductProof testProving() {
        return prover.generateProof(generatorParams, commitment, witness);
        // This is a demo/sample template for building your JMH benchmarks. Edit as needed.
        // Put your benchmark code here.
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    public void testVerifying1() throws VerificationFailedException {
        verifier1.verify(generatorParams, commitment, oneProof);
        // This is a demo/sample template for building your JMH benchmarks. Edit as needed.
        // Put your benchmark code here.
    }
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    public void testVerifying2() throws VerificationFailedException {
        verifier2.verify(generatorParams, commitment, oneProof);
        // This is a demo/sample template for building your JMH benchmarks. Edit as needed.
        // Put your benchmark code here.
    }

}
