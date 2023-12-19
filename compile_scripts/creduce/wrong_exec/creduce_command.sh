TENV=./test_env
rm -rf $TENV
mkdir -p $TENV
cp interesting.sh bpf.c $TENV
cd $TENV
creduce --n 1 ./interesting.sh ./bpf.c
