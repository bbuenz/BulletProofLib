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

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.rangeproof.*;
import org.bouncycastle.math.ec.ECPoint;
import org.openjdk.jmh.annotations.*;

import java.math.BigInteger;

@State(Scope.Benchmark)
public class ProofBenchmark {
    private final RangeProofSystem rangeProofSystem = new RangeProofSystem();
    private final RangeProofProver prover = new RangeProofProver();
    private final GeneratorParams generatorParams = GeneratorParams.generateParams(64);
    private ECPoint commitment;
    private PeddersenCommitment witness;
    private RangeProof oneProof;
    private RangeProofVerifier verifier = new RangeProofVerifier();

    @Setup
    public void setUp() {
        BigInteger number = ProofUtils.randomNumber(60);
        this.witness = new PeddersenCommitment(generatorParams.getBase(), number);
        commitment = witness.getCommitment();
        oneProof = testProving();
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    public RangeProof testProving() {
        return prover.generateProof(generatorParams, commitment, witness);
        // This is a demo/sample template for building your JMH benchmarks. Edit as needed.
        // Put your benchmark code here.
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    public void testVerifying() throws VerificationFailedException {
        verifier.verify(generatorParams, commitment, oneProof);
        // This is a demo/sample template for building your JMH benchmarks. Edit as needed.
        // Put your benchmark code here.
    }

}
