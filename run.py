import multiprocessing
import subprocess
import os
import glob

current_path = os.getcwd()

def execute_gem5_command(command):
    subprocess.run(command, shell=True)

if __name__ == "__main__":
    pwd = os.getcwd()
    pat='*.o'
    binary_names = glob.glob(os.path.join(f'{pwd}/tests/malloctest', pat))
    hash_lat=enc_lat=0
    processes = []
    for binary_name in binary_names:
        gem5_command = f"build/X86/gem5.opt \
            -d '{pwd}/m5/{binary_name}out' \
            configs/example/se.py \
            --caches --l1d_size=32kB --l1i_size=32kB --l1i_assoc=2 --l1d_assoc=4 \
            --l2cache --l2_size=1MB --l2_assoc=16 \
            --mem-type=DDR4_2400_8x8 --mem-size=2GB --pool_ids='0,1' \
            --sDMenable=true --hash_lat={hash_lat} --enc_lat={enc_lat}\
            --cpu-type=O3CPU \
            --cmd='{pwd}/tests/malloctest/{binary_name}.o'"

        process = multiprocessing.Process(target=execute_gem5_command, args=(gem5_command,))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()
