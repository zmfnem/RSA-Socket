#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <thread>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define TRUE 1
#define FALSE 0

using namespace std;

void    RecieveThread();
void    MakeKey();
int     CheckPrime(int n);
long    MakePrimeNumber();
long    mod(long n, long e, long m); 
int     MakePublicKey(long EulerPhi);  
int     MakePrivateKey(int e, long EulerPhi);
int     MakeCipherText(char *PlainText, long *CipherText, int Key); 
int     MakePlainText(long *CipherText, char *PlainText, int Key); 
int     GCD(int x, int y);

char    SendPublicKey[1024] = {0, };
int     N, AnotherN, MessageLength;
int     PublicKey, AnotherPublicKey, PrivateKey;
bool    AcceptFlag, RunFlag = true;
int     Socket, AnotherSocket;
char    SendBuffer[1024] = {0, }, RecieveBuffer[1024] = {0, };
long    SendData[1024] = {0, }, RecieveData[1024] = {0, };

int main(int argc, char **argv) {
    int                 Length;
    struct sockaddr_in  Address, AnotherAddress;

    switch(argc)    {
        case 2 : AcceptFlag = true; break;
        case 3 : AcceptFlag = false; break;
        default : cout << "Usage : " << argv[0] << " [ip_address] port" << "\n"; exit(-1);
    }

    if(AcceptFlag)  {
        if((Socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)   {
            cout << "socket() failed!" << "\n";
            exit(-1);
        }

        MakeKey();

        memset(&Address, 0, sizeof(Address));
        Address.sin_family = AF_INET;
        Address.sin_addr.s_addr = INADDR_ANY;
        Address.sin_port = htons(atoi(argv[1]));

        if(bind(Socket, (struct sockaddr*)&Address, sizeof(Address)) < 0)   {
            cout << "bind() failed!" << "\n";
            exit(-1);
        }

        if(listen(Socket, 10) < 0)  {
            cout << "listen() failed!" << "\n";
            exit(-1);
        }

        Length = sizeof(AnotherAddress);
        if((AnotherSocket = accept(Socket, (struct sockaddr*)&AnotherAddress, (socklen_t*)&Length)) < 0)   {
            cout << "accept() failed!" << "\n";
            exit(-1);
        }

        sprintf(SendPublicKey, "%d", N);
        send(AnotherSocket, SendPublicKey, 10, 0);

        recv(AnotherSocket, RecieveBuffer, sizeof(RecieveBuffer), 0);
        AnotherN = atoi(RecieveBuffer);

        sprintf(SendPublicKey, "%d", PublicKey);
        send(AnotherSocket, SendPublicKey, sizeof(int), 0);

        recv(AnotherSocket, RecieveBuffer, sizeof(RecieveBuffer), 0);
        AnotherPublicKey = atoi(RecieveBuffer);

        thread  Thread(RecieveThread);

        while(1)    {
            memset(&SendBuffer, 0, sizeof(SendBuffer));
            memset(&SendData, 0, sizeof(SendData));
            cin >> SendBuffer;

            if(!strcmp(SendBuffer, "exit"))  {
                cout << "disconnect" << "\n";
                                
                RunFlag = false;

                close(Socket);
                close(AnotherSocket);
                Thread.join();
            
                return 0;
            }

            MakeCipherText(SendBuffer, SendData, AnotherPublicKey);

            if(send(AnotherSocket, SendData, sizeof(SendData), 0) < 0) {
                break;
            }
        }
    }
    else    {
        if((Socket = socket(PF_INET, SOCK_STREAM, 0)) < 0)   {
            cout << "socket() failed!" << "\n";
            exit(-1);
        }

        MakeKey();

        memset(&Address, 0, sizeof(Address));
        Address.sin_family = AF_INET;
        Address.sin_addr.s_addr = inet_addr(argv[1]);
        Address.sin_port = htons(atoi(argv[2]));

        if(connect(Socket, (struct sockaddr*)&Address, sizeof(Address)) < 0)    {
            cout << "connect() failed!" << "\n";
            exit(-1);
        }

        sprintf(SendPublicKey, "%d", N);
        send(Socket, SendPublicKey, 10, 0);

        recv(Socket, RecieveBuffer, sizeof(RecieveBuffer), 0);
        AnotherN = atoi(RecieveBuffer);

        sprintf(SendPublicKey, "%d", PublicKey);
        send(Socket, SendPublicKey, sizeof(int), 0);
        
        recv(Socket, RecieveBuffer, sizeof(RecieveBuffer), 0);
        AnotherPublicKey = atoi(RecieveBuffer);

        thread  Thread(RecieveThread);
        
        while(1)    {
            memset(&SendBuffer, 0, sizeof(SendBuffer));
            memset(&SendData, 0, sizeof(SendData));

            cin >> SendBuffer;

            if(!strcmp(SendBuffer, "exit"))  {
                cout << "disconnect" << "\n";
                                
                RunFlag = false;

                close(Socket);
                close(AnotherSocket);
                Thread.join();
            
                return 0;
            }

            MakeCipherText(SendBuffer, SendData, AnotherPublicKey);
            
            if(send(Socket, SendData, sizeof(SendData), 0) < 0) {
                break;
            }
        }
    }
}

void RecieveThread()    {
    while(RunFlag)    {
        memset(&RecieveBuffer, 0, sizeof(RecieveBuffer));
        memset(&RecieveData, 0, sizeof(RecieveData));

        if(AcceptFlag)  {
            if(recv(AnotherSocket, RecieveData, sizeof(RecieveData), 0) < 0)   {
                if(RunFlag) {
                    cout << "recv() failed!" << "\n";
                }
                return ;
            }
        }
        else    {
            if(recv(Socket, RecieveData, sizeof(RecieveData), 0) < 0)   {
                if(RunFlag) {
                    cout << "recv() failed!" << "\n";
                }
                return ;
            }
        }

        MakePlainText(RecieveData, RecieveBuffer, PrivateKey);

        if(RecieveBuffer[0] != '\0')  {
            cout << "[상대방] > " << RecieveBuffer << "\n";
        }
    }
}

void MakeKey()  {
    long    EulerPhi = MakePrimeNumber();

    PublicKey = MakePublicKey(EulerPhi);
    PrivateKey = MakePrivateKey(PublicKey, EulerPhi);
}

int GCD(int x, int y)   {
    int mod;

    if (x < y)   {
      int tmp = x;
      x = y;
      y = tmp;
    }

    mod = x % y;

    if (mod == 0)   {
      return y;
    }
    else    {
      return GCD(y, mod);
    }
}

long MakePrimeNumber() {
    int     Prime[2]; // P와 Q 두개의 솟수는 공개키, 비밀키의 기본 소수
    time_t  Time;

    srand((unsigned int)time(&Time)); //난수생성
    for (int i = 0; i < 2; ++i)  {            // 2개의 임의의 솟수 P와 Q를 생성한다.
        do {
            Prime[i] = rand() % 1000; // 3자리수로 고정      
        } while (CheckPrime(Prime[i]));    //소수가 아니면 반복한다.
    }
    N = Prime[0] * Prime[1];      // 두개의 소수 p,q를 이용해 n값 생성
    return (Prime[0] - 1) * (Prime[1] - 1);  // 오일러 파이값;
}


int MakePublicKey(long EulerPhi)   {
    long e;

    do   {
        e = rand() % 100;
        if ((e < EulerPhi) && (GCD(e, EulerPhi) == 1))  {
            return e;
        }
    } while(1);

    return e;
}

int MakePrivateKey(int e, long EulerPhi)   {
    int d = 0;

    while (((e * d) % EulerPhi) != 1)  {
        ++d;
    }

    return d;   
}


int CheckPrime(int n)   {
    int Limit;

    if (!(n % 2))   {
        return TRUE;
    }

    Limit = (int)sqrt(n) + 1;

    for (int i = 3; i <= Limit; i += 2) {
        if (!(n % i))   {
            return TRUE;
        }
    }

    return FALSE;
}

long mod(long n, long e, long m)    {
    long Rest = 1;

    for (int i = 1; i <= e; ++i) {
        Rest *= n;   
        Rest %= m;
    }
    return Rest;
}


int MakeCipherText(char *PlainText, long *CipherText, int Key) {
    MessageLength = strlen(PlainText);

    for (int i = 0; i < MessageLength; ++i) {
        CipherText[i] = (long)mod(PlainText[i], Key, AnotherN);
    }
    CipherText[MessageLength] = '\0';

    return 0;
}

int MakePlainText(long *CipherText, char *PlainText, int Key) {
    int i;
    for (i = 0; CipherText[i] != '\0'; ++i) {
        PlainText[i] = (char)mod(CipherText[i], Key, N);
    }
    PlainText[i] = '\0';

    return 0;
}