import re
import sys
from collections import defaultdict
import gc
import numpy as np
#from memory_profiler import profile
#from blist import sortedset
ADD=100
CMUL=101

verbose=0



class missingdict(defaultdict):
    def __missing__(self, key):
        return self.default_factory()
    def __repr__(self):
        return str(dict(self))
#f = open('two-matrix-p0-b32.arith.txt','r')

def dotprod(a,b):
    mul=lambda x:x[0]*x[1]
    summ=lambda x,y:x+y
    c=reduce(summ,map(mul,zip(a,b)))
    return c

'''
def printconstraints(ct) :
    for ci in ct:
        s=''
        for i in range(len(ci)):
            if ci[i]!=0: s+=' W'+str(i)+'*'+str(ci[i])
        if s!='' : print s
'''
def writeout(N,Q,wire_state,constraints_table,constraints_constants,index, filename):
    fout = open(str(filename),'w')
    fout.write("# Quick and dirty input file.\n# Usage: from exampleout import * \n# This will load the values below for testing  \n\n")
    fout.write("import numpy as np  \n\n")
    fout.write("N="+str(N))
    fout.write("\n")
    fout.write("Q="+str(Q))
    fout.write("\n")
    fout.write("Constr=np."+repr(constraints_table))
    fout.write("\n")
    fout.write("state=np."+repr(wire_state))
    fout.write("\n")
    fout.write("C=np."+repr(constraints_constants))
    fout.write("\n")
    fout.write("index="+str(index))
    fout.write("\n")



#@profile
def build_matrix(fc,inputlist,fix_req):
    nextfree=-1

    addlist=[]
    multilist=[]
    splitlist=[]
    inputs=set([])
    #outputs=set([])
    state=[]
    currentinput=0
    for line in fc:

        #m=re.search('const-mul-0 in 1 <(\d+)> out 1 <(\d+)>',line)
        #if m:
        #    #print 'CM-0'
        #    addlist.append((0,int(m.group(1)),int(m.group(2)),CMUL))
        #    state[int(m.group(2))]=0#*state[int(m.group(1))]
        #    continue
        m=re.search('const-mul-([0-9a-f]+) in 1 <(\d+)> out 1 <(\d+)>',line)
        if m:
            v=int(m.group(1),16)
            #print 'const mul',m.group(1),v
            addlist.append((v,int(m.group(2)),int(m.group(3)),CMUL))
            state[int(m.group(3))]=v*state[int(m.group(2))]
            continue

        m=re.search('const-mul-neg-([0-9a-f]+) in 1 <(\d+)> out 1 <(\d+)>',line)
        if m:
            #print 'CM-1'
            v=int(m.group(1),16)
            #print 'const mul-',m.group(1),v
            addlist.append((-v,int(m.group(2)),int(m.group(3)),CMUL))
            state[int(m.group(3))]=-v*state[int(m.group(2))]
            continue
       # m=re.search('const-mul-ffffffff in 1 <(\d+)> out 1 <(\d+)>',line)
       # if m:
       #     print 'CM-TC'
       #     addlist.append((4294967295,int(m.group(1)),int(m.group(2)),CMUL))
       #     state[int(m.group(2))]=4294967295*state[int(m.group(1))]
       #     continue

        m=re.search('split in 1 <(\d+)> out (\d+) <(\d+)(\s*\d+)*>',line)
        if m:
            #print 'CM-0'
            #print '****************'
            #print 'split in gate #',int(m.group(1))
            #print 'out size',int(m.group(2))
            #print 'start,last',int(m.group(3)),int(m.group(4))
            splitlist.append((int(m.group(1)),[int(m.group(3))+i for i in xrange(int(m.group(2)))]))
            t=state[int(m.group(1))]
            extra_len_multilist+=int(m.group(2))
            for i in xrange(int(m.group(2))):
                state[int(m.group(3))+i]=t%2
                t=t//2
                #sum = <in>
            continue

        m=re.search('mul in 2 <(\d+) (\d+)> out 1 <(\d+)>',line)
        if m:
            #print 'Mul'
            #multilist.append((int(m.group(1)),int(m.group(2)),int(m.group(3))))
            multilist[len_multilist][0]=int(m.group(1))
            multilist[len_multilist][1]=int(m.group(2))
            multilist[len_multilist][2]=int(m.group(3))

            state[int(m.group(3))]=state[int(m.group(1))]*state[int(m.group(2))]
            len_multilist+=1

            continue

        m=re.search('add in 2 <(\d+) (\d+)> out 1 <(\d+)>',line)
        if m:
            #print 'Add'
            addlist.append((int(m.group(1)),int(m.group(2)),int(m.group(3)),ADD))
            state[int(m.group(3))]=state[int(m.group(1))]+state[int(m.group(2))]
            continue

        m=re.search('total (\d+)',line)
        if m:
            #print 'Tot'
            if nextfree>=0 : quit("total encountered twice")
            nextfree=int(m.group(1))
            #state=[-1]*(3*nextfree)
            state=np.full(3*nextfree, 0,dtype=object) #assuming no overflow
            multilist=np.full((nextfree*5,3),-1,dtype=int)#also np.int64
            #we will check if wire# is in multilist, so the dummy value must NOT be
            #possible to reach when enumerating inputs
            len_multilist=0
            extra_len_multilist=0
            continue

        m=re.search('input (\d+)',line)
        if m:
            #print 'In'
            inputs.add(int(m.group(1)))
            state[int(m.group(1))]=inputlist[currentinput]
            currentinput+=1
            continue
       # m=re.search('output (\d+)',line)
       # if m:
       #     break
       #     #print 'out'
       #     #outputs.add(int(m.group(1)))
       #     #print state[int(m.group(1))]
       #     continue
    fc.close()
    if fix_req: #This is slow if not needed
        print 'flattening'
        mf=multilist.flatten()
        #print inputs
        #print multilist
        if verbose: print 'flat'

        missing=[s for s in inputs if not s in mf]
        del mf
        if verbose: print 'ok'

        #print missing
        #print 'missing =',missing
        mxi= max(inputs) #presumed to be dummy 1 wire
        for mi in missing:
                #print '***',mi
                multilist[len_multilist][0]=mi
                multilist[len_multilist][1]=mxi
                multilist[len_multilist][2]=nextfree
                state[nextfree]=state[mi]*state[mxi]
                len_multilist+=1
                nextfree+=1
    #multilist.resize((len_multilist+extra_len_multilist,3)) #[0:len_multilist]
    #print state
    if verbose: print 'matrix done'
    return nextfree,inputs,addlist,multilist,len_multilist,splitlist,state   #outputs,


def addconstraint(index,ct,*clist):
    #c=[0]*maxwires
    c=missingdict(long)
    for cst in clist:
        if cst[1]!=0 :
            c[cst[0]]=cst[1]
            index[cst[0]].add(len(ct))
    ct.append(c)
    return

def addconstraint_opt(index,ct,c1,c2):
# addconstraint(index,ct,(left,1),(nextfree,-1))
    c=missingdict(long)
    c[c1]=1
    c[c2]=-1
    index[c1].add(len(ct))
    index[c2].add(len(ct))
    ct.append(c)
    return


#@profile
def encoding_multi(multilist,len_multilist,splitlist,nextfree,state,inputs,maxwires):
    #multilist2=[]
    used_inputs=[]
    not_fresh_inputs=[1 for _ in xrange(maxwires)]
    for inp in inputs:
        not_fresh_inputs[inp]=0
    idx=0
    ct=[]
    index=np.array([set() for i in xrange(maxwires)])

    #for mli in multilist:
    for i in xrange(len_multilist):
        idx+=1
        if idx%150000==0 and verbose: print idx," Multi of ",len(multilist)
        (left,right,out)=multilist[i]
        #left=mli[0]
        #right=mli[1]
        #out=mli[2]
        #print left,right,out
        #if (not (left in inputs)) or (left in used_inputs) :
        if not_fresh_inputs[left]:
            #addconstraint(index,ct,(left,1),(nextfree,-1))
            addconstraint_opt(index,ct,left,nextfree)
            state[nextfree]=state[left]
            left=nextfree
            nextfree+=1
            #print 'dup left'
        else:
            not_fresh_inputs[left]=1
        #if (not (right in inputs)) or (right in used_inputs)  :
        if not_fresh_inputs[right]:
            #addconstraint(index,ct,(right,1),(nextfree,-1))
            addconstraint_opt(index,ct,right,nextfree)
            state[nextfree]=state[right]
            right=nextfree
            nextfree+=1
            #print 'dup right'
        else:
            #used_inputs.append(right)
            not_fresh_inputs[right]=1
        #if idx%50000==0 : print multilist[i],ct[i],state[i]
        #print left,right,out
        #multilist2.append((left,right,out))
        multilist[i]=(left,right,out)

    ml_insertpoint=len_multilist
    #multilist.resize((maxwires,3))
    for split in splitlist:
        #print split[0]
        #print split[1]
        for zowire in split[1]:
            addconstraint_opt(index,ct,zowire,nextfree)  #dupe
            state[nextfree]=state[zowire]
            state[nextfree+1]=state[zowire]*state[zowire] #square
            addconstraint_opt(index,ct,zowire,nextfree+1) #square==orig
            #multilist.append((zowire,nextfree,nextfree+1))
            multilist[ml_insertpoint][0]=zowire
            multilist[ml_insertpoint][1]=nextfree
            multilist[ml_insertpoint][2]=nextfree+1
            ml_insertpoint+=1
            nextfree+=2
        addconstraint(index,ct,*zip([split[0]]+split[1],[-1]+[2**i for i in xrange(len(split[1]))]))


    #print multilist==multilist2
    #return np.array(multilist).flatten(),np.array(state,dtype=object),ct,index
    return multilist[0:ml_insertpoint].flatten(),np.array(state,dtype=object),ct,index


def encoding_add(addlist,ct,index):

    idx=0
    #print ct
    for addi in reversed(addlist):
        left=addi[0]
        right=addi[1]
        out=addi[2]
        operation=addi[3]
        idx+=1
        if idx%150000==0 and verbose : print idx," Adds of ",len(addlist)
        #print left,right,out
        if operation==ADD :
            for i in index[out]:
                if ct[i][out]==0 : continue
                #print 'fixing constraint (add encoding)'
                ct[i][right]+=ct[i][out]
                index[right].add(i)
                ct[i][left]+=ct[i][out]
                index[left].add(i)
                del ct[i][out] #or set to 0
        if operation==CMUL :
            #print ct
            #print '******',addi
            for i in index[out]:
                #print '-----'
                #if ci[out]==0 : continue
                #print 'fixing constraint (const mul encoding)'
                ct[i][right]+=left*ct[i][out]
                index[right].add(i)
                del ct[i][out] #or set to 0

            #print ct

    return ct
#@profile
def encoding_add_mult(multilist,len_multilist,splitlist,addlist,nextfree,state,inputs,maxwires):
    multilist,state,ct,index=encoding_multi(multilist,len_multilist,splitlist,nextfree,state,inputs,maxwires)
    ct=encoding_add(addlist,ct,index)


    return state,ct,multilist
#@profile
def remap_table(state,ct,maxwires,multilist):
    rt=np.zeros(maxwires,dtype=int)      #renumbering lookup table (wire w goes where?)
    #rti=np.empty(maxwires2,dtype=int)    #renumbering inverse tale (new wire w2 comes from where?)

    rt[multilist]=np.arange(maxwires)
    ct,index=renumbering(ct,rt,maxwires)

    state2=state[multilist]
    state=[long(s) for s in state2] #numpy optional
    #index=[int(s) for s in index]
    return state,ct,index
#@profile
def renumbering(ct,rt,maxwires):
    #index=np.array([set() for i in xrange(maxwires)])
    index=[set() for i in xrange(maxwires)]
    #print maxwires
    #ct2=np.array([missingdict(long) for i in xrange(len(ct))])

    for j in xrange(len(ct)):
        temp=missingdict(long)
        for i in ct[j]:
            #if j==1: print i,j,rt[i],ct2[j]
            if ct[j][i]!=0:
                #(ct2[j])[rt[i]]=ct[j][i]
                temp[rt[i]]=ct[j][i]
                #print i,j,rt[i]
                index[rt[i]].add(j)
        ct[j]=temp
    #print ct2[0],ct[1],ct[0]==ct[1]
    return ct,index



#start

#@profile
def parser(fc,fv,fix_req):


    exec(fv.read())




    nextfree,inputs,addlist,multilist,len_multilist,splitlist,state=build_matrix(fc,inputlist,fix_req)
    del inputlist


    #print 'Inputs:', inputs
    #print 'Outputs:', outputs
    print 'Addition Gates and Mul. by constant', len(addlist)
    #print addlist
    print 'Multiplication Gates', len_multilist
    #print 'Con-0 Multi. Gates', len(conmultilist)

    #Initialize constraints table
    maxwires=nextfree+2*len(multilist)+sum([2*len(i[1]) for i in splitlist])+1


    #index=[set() for i in xrange(maxwires)]



    if verbose: print "Encoding multiplications and doubling wires..."

    #Duplicate all multiplication-inputs w/o input flag + adjust consistency
    #inputs get one 'life' free

    #multilist,state,ct,index=encoding_multi(multilist,nextfree,state,inputs,maxwires)
    #del inputs
    #gc.collect()





    if verbose: print "Encoding additions"

    #ct=encoding_add(addlist,ct,index)
    state,ct,multilist=encoding_add_mult(multilist,len_multilist,splitlist,addlist,nextfree,state,inputs,maxwires)
    del inputs, addlist
    #gc.collect()
    #print len(ct)
    #printconstraints(ct)

    #print "ct[1]=",ct[1]



    #printconstraints(ct)


    #wires_in_constraints = set([i for i in xrange(maxwires) for ci in ct if ci[i]!=0 ])
    # Kills performance dead

    #wires_in_multiplications= set([w for mi in multilist2 for w in mi])

    #print wires_in_constraints
    #print wires_in_multiplications
    #print wires_in_constraints.issubset(wires_in_multiplications)


    #offset is 1 numbers wires as 1,2,3, offset=0 uses 0,1,2
    #offset=0

    #maxwires2 = len(multilist)*len(multilist[0])+offset
    #print maxwires2, len(multilist2)*len(multilist2[0])

    ## Compact numbering
    ## Built renumbering table
    if verbose: print "Building remap table..."

    state,ct,index=remap_table(state,ct,maxwires,multilist)

    del multilist
    gc.collect()


    #print ct2
    if verbose: print "Remap table ready, renumbering..."
    #ct,index=renumbering(ct,rt,maxwires2)





            #if j==1: print ct2[j]
    #print "ct2[1]=",ct2[1]
    #print "ct3[1]=",ct3[1]
    #del rt
    #gc.collect()
    if verbose: print "Renumbering Done..."
    #for ci in ct2:
    #    s=''
    #    for i in range(maxwires2):
    #        if ci[i]!=0: s+=' W'+str(i)+'*'+str(ci[i])
        #if s!='' : print s
    if verbose: print "Renumbering state"
    #inputs2=set([rt[w] for w in inputs])
    #outputs2=set([rt[w] for w in outputs])
    #print len(state),maxwires2,type(rti[0])
    #state=np.array([state[rti[i]] for i in xrange(maxwires2)])
    #state=state[rti]
    #del rti
    #   for o in outputs2 : print o,state2[o]
    #print inputs2,outputs2
    #print multilist3
    #print state2
    #for ci in ct2:
    #print dotprod(state2,ci)
    #assert dotprod(state2,dense(ci,maxwires2))==0
    #C=[0]*len(ct2)
    if verbose: print "Almost done..."



    N=int(len(state)/3)
    #print 'N', N
    Q=len(ct)
    #Constr=np.array(ct)
    #Constr=ct2

    #state=np.array(state2)
    #state=state2
    #print ct[0],ct[0].keys(),zip(*ct[0].items())
    #ct2=np.array([zip(*i.items()) for i in ct])


    #print ct2[-1,0]
    #C=np.zeros(Q,dtype=np.int)
    C=[0]*len(ct)

    #index=np.array(index)
    #index=index2
    #print Constr.nbytes,state.nbytes, index.nbytes

    gc.collect()
    #np.set_printoptions(threshold='nan')
    #writeout(N,Q,state,ct,C,index,"Input-p2.py")
    #gc.collect()
    if verbose: print "Parsing Complete"
    #print state
    #print ct
    return mm,nn,N,Q,ct,state,C,index
