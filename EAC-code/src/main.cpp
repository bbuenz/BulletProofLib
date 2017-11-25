
#include <stdio.h>
#include <time.h>
#include <vector>
#include <fstream>
#include <cassert>
#include <algorithm>
#include <string>
#include <sstream>      // std::stringstream


#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>

#include <NTL/mat_ZZ.h>
#include <NTL/matrix.h>
#include <NTL/vec_vec_ZZ.h>
NTL_CLIENT



 int main(){
     cout<<"Hello World"<<endl;
     ifstream ist("polyfile_before.txt");
     if(!ist) cout<<"Can't open file"<< endl;

     string s_temp;
     ZZ mod;
     long size_vec;
     long size_f;
     long size_pt;
     ist>>s_temp;

     conv(mod,s_temp.c_str());
     ZZ_p::init(mod);
     cout<<mod<<endl;
     ZZ_pX f,pt,res;
     res=ZZ_pX(); //zero
     ist>>size_f;
     ist>>size_pt;
     ist>>size_vec;
     
     //reads the vector t_1
    //l=2*m;
    //for (i = 0; i<l; i++){
    //   ist >> chal_x6->at(i);
    //}

     cout<<"Expecting "<<size_vec*(size_f+size_pt)<<" entries"<<endl;
     //ist>>c;
     int i,j;
     
     for (i=0;i<size_vec;i++){
         ist>>f;
         //cout<<f;
         ist>>pt;
         //cout<<pt;
         res+=f*pt;
         //cout<<res;
     }
     ofstream ost("polyfile_after.txt");
     //ost<<res;
     stringstream st;     // line A
     st << res;              // line B
     std::string s = st.str();      // Line D
     std::replace( s.begin(), s.end(), ' ', ','); // replace all 'x' to 'y'
     //ost<<"hvec=";
     ost<<s;

     
    return 1;
}
