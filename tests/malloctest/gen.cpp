#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
using namespace std;
int main()
{
    srand(time(NULL));
    // int n = 100000, m = 190000;
    int n = 50, m = 30;
    cout << n << " " << m << endl;
    for (int i = 0; i < m; i++)
    {
        cout << rand() % n + 1 << " " << rand() % n + 1 << endl;
    }
    return 0;
}