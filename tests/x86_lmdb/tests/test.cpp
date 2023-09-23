#include <cstdio>
#include <cstdlib>
extern "C"
{
    #include <lmdb.h>
}
using namespace std;
int main()
{
    int res;
    MDB_env *env;
    MDB_dbi dbi;
    MDB_val key, data;
    MDB_txn *txn;
    MDB_cursor *cursor;

    //init lmdb
    printf("lmdb version:%s\n",mdb_version(0, 0, 0));

    res = mdb_env_create(&env);
    if(res){
        printf("mdb_env_create error,error:%s\n", mdb_strerror(res));
        return -1;
    }
 
    res=mdb_env_set_mapsize(env,1024*1024*1024);
    if(res!=0){
        printf("mdb_env_set_mapsize error, detail:%s\n", mdb_strerror(res));
        return -1;
    }
    
    res = mdb_env_open(env, ".", 0, 0644);
    if(res){
        printf("mdb_env_open error, detail:%s\n", mdb_strerror(res));
        return -1;
    }
 
    res = mdb_txn_begin(env, NULL, 0, &txn);
    if(res){
        printf("mdb_txn_begin error, detail:%s\n", mdb_strerror(res));
        return -1;
    }
 
    res = mdb_dbi_open(txn, NULL, 0, &dbi);
    if(res){
        printf("mdb_dbi_open error, detail:%s\n", mdb_strerror(res));
        return -1;
    }
    //write data to lmdb
    unsigned long long count=10;
    unsigned long long value=0;

    unsigned long long i=0;
    for(;i<count;++i){
        value=i+1;

        key.mv_size =sizeof(i);
        key.mv_data =(void*)&i;
        data.mv_size = sizeof(value);
        data.mv_data = (void*)&value;

        res = mdb_put(txn, dbi, &key, &data, 0);
        if(res!=0)
        {
            printf("mdb_put error,res=%d, detail:%s",res,mdb_strerror(res));
            break;
        }
    }

    res = mdb_txn_commit(txn);
    if (res) {
        printf("mdb_txn_commit error:%d:%s",res, mdb_strerror(res));
        return -1;
    }
    res = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    res = mdb_cursor_open(txn, dbi, &cursor);
    //read data from lmdb

    unsigned long long read_count=0;
    while ((res = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
        int r_key=*(int *)key.mv_data;
        int r_value=*(int *)data.mv_data;
        ++read_count;
        printf("\t<%d,%d>\n",r_key, r_value);
    }

    printf("read count:%lld\n", read_count);
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    //free
    mdb_dbi_close(env, dbi);
    mdb_env_close(env);
    return 0;
}
 
