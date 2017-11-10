from arithparser3 import *
import math
circuit_type=sys.argv[1]
circuit_size=sys.argv[2]


usesmallints=1


circuit_file="circ/"+circuit_type+"-"+circuit_size+"-b32.arith.txt"
value_file="circ/"+circuit_type+"-"+circuit_size+"-b32.values.txt"

def open_filename (filename):
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
f=open(sys.argv[3], 'w')
print "This is it Wa"
for const in Constr:
	for i in xrange(N):
		f.write(str(const[3*i])+' ')
	f.write('\n')
for const in Constr:
	for i in xrange(N):
		f.write(str(const[3*i+1])+' ')
	f.write('\n')
for const in Constr:
	for i in xrange(N):
		f.write(str(const[3*i+2])+' ')
	f.write('\n')

