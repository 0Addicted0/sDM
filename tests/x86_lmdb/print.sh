dbdir=$(pwd)/tests/db
lmdb="$(pwd)"
gem5="$lmdb/../.."
echo "lmdb: $lmdb"
# $lmdb/build/bin/mdb_dump -p $dbdir/ # 打印数据库内容
$lmdb/build/bin/mdb_dump -p $gem5/db/$1 # 打印数据库内容 $1=[hello,test,...]
