#Main Proto
import sys,re
from petlib.ec import *
from petlib.bn import *
from hashlib import sha256
from Commitment import *
from LPoly import*
from PolyCommit import *
from Recursion import *
from arithparser3 import *
import time
import math
start = time.clock()

verbose=0

def dense(d,maxitems):
    return[d[x] for x in xrange(maxitems)]

if len(sys.argv)<=2 :
    print "Usage: Wrapper.py circuit_type size"
    exit(-1)

circuit_type=sys.argv[1]
circuit_size=sys.argv[2]
if sys.argv[3]=='log' :
    import Main_log
    use_log=1
    prover_f=Main_log.prover_sat_log
    verifier_f=Main_log.verifier_sat_log
else:
    import Main
    use_log=0
    prover_f=Main.prover_sat
    verifier_f=Main.verifier_sat

    

    
usesmallints=1
    

circuit_file="circ/"+circuit_type+"-"+circuit_size+"-b32.arith.txt"
value_file="circ/"+circuit_type+"-"+circuit_size+"-b32.values.txt"


print "Using input files:",str(circuit_file),",",str(value_file)

def open_filename(filename):
     try:
         handle = open(str(filename),'r')
     except(OSError,IOError) as e:
         print "Could not open circuit file"
         print str(e)
         exit(-1)
     return handle


fc=open_filename(circuit_file)
fv=open_filename(value_file)




#### FIX FIX FIX
#hack to fix pre-processing
fix_req=0
if circuit_type=='one-matrix' or circuit_type=='lgca' or circuit_type=='sha' : fix_req=1
m,n,N,Q,Constr,state,C,index=parser(fc,fv,fix_req)


if use_log:
    m=2
    m=int(math.log(N,2))
    #m*=m
    n=(N+m-1)/m
    m1=int(math.sqrt(int(m)))
    n1=int(math.ceil(int((4*m+2)/m1)))+1
    n2=int(math.ceil(int(3*m/m1)))+1
    if n>=m1*(n1+n2):
        ks=n
    else: ks=m1*(n1+n2)
print 'N=',N


#Obtain:
#N=len(wire_state)/3
#Q=len(constraints_table)
#Constr=constraints_table
#state=wire_state
#C=constraints_constants

# Do proof // Do ver
if verbose: print "Preprocessing done..."
if verbose: print "_____________________"
elapsed = (time.clock() - start)
tpp=elapsed
print str(elapsed)+" Seconds Preprocessing"
start = time.clock()
if verbose: print "Generating commitment key"
#m=mm
#n=nn
m1=int(math.sqrt(int(m)))
n1=int(math.ceil(int((4*m+2)/m1)))+1
n2=int(math.ceil(int(3*m/m1)))+1
ck=commitment_key_gen(max(n+3,8*m))
   
if verbose: print "Keygen done..."
if verbose: print "_____________________"
elapsed = (time.clock() - start)
tkg=elapsed
print str(elapsed)+" Seconds Keygen"

start = time.clock()
Trans,comcost=prover_f(ck,m,n,N,m1,n1,n2,Q,state,Constr,index,C,usesmallints)
elapsed = (time.clock() - start)
tpv=elapsed
print str(elapsed)+" Seconds Prover"

start = time.clock()
print  verifier_f(ck,m,n,N,m1,n1,n2,Q,Constr,index,C,Trans,usesmallints)
elapsed = (time.clock() - start)
tvf=elapsed
print str(elapsed)+" Seconds Verifier"

print "Communication (GE,FE): ",comcost
