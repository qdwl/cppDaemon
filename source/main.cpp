#include <iostream>
#include "daemon.h"

int TaskMain(int argc,char * argv[])
{
    std::cerr<<"argc  "<<argc<<std::endl;
    for(int i = 0 ; i < argc ; i++)
    {
        std::cerr<<"argv "<<i << "  Value "<<argv[i]<<std::endl;
    }
    while(1)
    {
        sleep(2);
        std::cerr<<"Child Thread"<<std::endl;
    }
}
int main(int argc,char * argv[])
{
    std::cout<<"MainFunc"<<std::endl;
    oc::daemon::MainStub(argc,argv,TaskMain);
    return 0;
}