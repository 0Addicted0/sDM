#include <iostream>
#include <stdio.h>
#include <string.h>
#include "gem5/sdmmalloc.h"
using namespace std;
#define sdm 1
typedef struct _edge
{
    int to, next;
} edge;
int n, m, pos; // n = 100000,m = 200000
int *vis;
int *head;
edge *e;
void dfs(int x)
{
    vis[x] = 1;
    for (int i = head[x]; i; i = e[i].next)
    {
        int u = e[i].to;
        if (!vis[u])
        {
            dfs(u);
        }
    }
};
void buildEdge(int a, int b)
{
    e[++pos].next = head[a];
    e[pos].to = b;
    head[a] = pos;
}
void init()
{
    // 这里进行资源分配,换成sdmmalloc
#ifdef sdm
    head = (int *)sdmmalloc(sizeof(int) * (n+1));
    vis = (int *)sdmmalloc(sizeof(int) * (n+1));
    e = (struct _edge *)sdmmalloc(sizeof(edge) * (m+1));
#endif

#ifndef sdm
    head = (int *)malloc(sizeof(int) * (n+1));
    vis = (int *)malloc(sizeof(int) * (n+1));
    e = (struct _edge *)malloc(sizeof(edge) * (m+1));
#endif
    // head = (int *)malloc(sizeof(int) * (n+1));
    // vis = (int *)malloc(sizeof(int) * (n+1));
    // e = (struct _edge *)malloc(sizeof(edge) * (m+1));

    memset(head, 0, sizeof(int) * (n+1));
    memset(vis, 0, sizeof(int) * (n+1));
}
void deinit()
{
#ifdef sdm
    sdmfree(head);
    sdmfree(vis);
    sdmfree(e);
#endif
#ifndef sdm
    free(head);
    free(vis);
    free(e);
#endif
}
int main()
{
    cin >> n >> m;
    cout << n << " " << m << endl;
    init();
    for (int i = 0; i < m; i++)
    {
        int a, b;
        cin >> a >> b;
        buildEdge(a, b);
    }
    cout << "reading over!" << endl;
    uint64_t cnt = 0;
    for (int i = 1; i <= n; i++)
    {
        if (!vis[i])
        {
            cnt++;
            dfs(i);
        }
    }
    cout << "block:" << cnt << endl;
    deinit();
    return 0;
}