#include <iostream>
#include <vector>
#include <fstream>
#include <iomanip>
#include <string>
#include <stdint.h>
#include <sstream>
#include <sys/mman.h>
#include <cstdio>
#include <cstdlib>
#include <string.h>

using namespace std;

int SIZE = 0x100000;
long long unsigned int OFFSET = 0X0000100000000000;

int main(int argc,char *argv[])
{
	string delimiter = ":";
	ifstream test ("test.txt");
	size_t pos = 0;
	int cnt=0;
	string op,addr,size,s;
	unsigned long address,sz;
	if(test.is_open())
	{
		char *shadow;
		int position,Offset;
		shadow = (char *)mmap((caddr_t)OFFSET,SIZE/8,PROT_READ | PROT_WRITE , MAP_SHARED|MAP_ANONYMOUS,4,0);
		memset(shadow,0,(SIZE/8)*sizeof(char));
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
				iss >> hex >> address;
				cout <<  "Address : " << address << endl;
				istringstream iss1(size);
				iss1 >> hex >> sz;
				cout << "Size : " << sz << endl;
				string ARCH("64bit");
				if(op=="write")
				{
					for(int i=0;i<sz;i++)
					{
						Offset = (address>>3);
						position = 7 - (address&7);
						cout<<"Offset :"<<Offset<<"position :"<<position<<endl;
						shadow[Offset] = (shadow[Offset])|(1<<position);
						//	cout<<hex<<shadow[Offset]<<endl;
						printf("%x\n",shadow[Offset]);
						address++;
					}
				}
				else if(op=="image_load")
				{
					for(int i=0;i<sz;i++)
					{
						Offset = (address>>3);
						position = 7 - (address&7);
						shadow[Offset] = (shadow[Offset])&(~(1<<position));
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
