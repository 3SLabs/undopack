#include <iostream>
#include <unistd.h>
#include <vector>
#include <fstream>
#include <iomanip>
#include <string>
#include <stdint.h>
#include <sstream>
#include <sys/mman.h>
#include <sys/types.h>
#include <cstdio>
#include <cstdlib>
#include <string.h>

#ifndef MAP_ANONYMOUS
#  define MAP_ANONYMOUS MAP_ANON
#endif

using namespace std;

unsigned int SIZE = 0xffffffff;
long long unsigned int OFFSET = 0X800000000000;

int main(int argc,char *argv[])
{
	//	printf("%u\n",SIZE);
	string delimiter = ":";
	ifstream test ("test.txt");
	size_t pos = 0;
	int cnt=0;
	string op,addr,size,s;
	long long unsigned address,sz;
	if(test.is_open())
	{
		char *shadow;
		long long unsigned int position,Offset;
		shadow = (char *)mmap((void *)OFFSET,(size_t)SIZE/8,PROT_READ | PROT_WRITE , MAP_SHARED|MAP_ANONYMOUS,4,0);
		//printf("%x\n",shadow);
		memset((void *)shadow,0,(SIZE/8)*sizeof(char));
		bool b;
		if((caddr_t)shadow !=(caddr_t)-1)
		{
			while(getline(test,s))
			{
				cnt = 0;
				while((pos=s.find(delimiter))!=string::npos)
				{
					if(cnt==0)
						op = s.substr(0,pos);
					else if(cnt==1)
						addr = s.substr(0,pos);
					cnt++;
					s.erase(0,pos+delimiter.length());
					if(cnt==2)
						size=s;
				}
				istringstream iss(addr);
				iss>> address;
				//cout <<  "Address : " << address << endl;
				istringstream iss1(size);
				iss1 >> sz;
				//cout << "Size : " << sz << endl;
				cout<<op<<endl;
				string ARCH("64bit");
				if(op=="write")
				{
					for(int i=0;i<sz;i++)
					{
						Offset = (address>>3);
						position = 7 - (address&7);
						shadow[Offset] = (char )(shadow[Offset])|(1<<position);
						address++;
					}
				}
				else if(op=="image_load")
				{
					for(int i=0;i<sz;i++)
					{
						Offset = (address>>3);
						position = 7 - (address&7);
						shadow[Offset] = (char)(shadow[Offset])&(~(1<<position));
						address++;
					}
				}
			}
		}
		test.close();
	}
	else
		cout << "Unable to open test File\n";

	return 0;
}
