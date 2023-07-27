import multiprocessing
import subprocess
import os
import glob

current_path = os.getcwd()

def execute_gem5_command(command):
    subprocess.run(command, shell=True)

if __name__ == "__main__":
    pwd = os.getcwd()
    test_dir=f"{pwd}/tests/malloctest"
    pat='*.o'
    # binary_names = glob.glob(os.path.join(f'{pwd}/tests/malloctest', pat))
    binary_names = ['aes.o']
    modes = ['true','false']
    hash_lat=enc_lat=0
    processes = []
    for binary_name in binary_names:
        for mode in modes:
            gem5_command = f"build/X86/gem5.opt \
                -d '{pwd}/m5/{binary_name}-{mode}-out' \
                configs/example/se.py \
                --caches --l1d_size=128B --l1i_size=128B \
                --mem-type=DDR3_1600_8x8 --mem-size=512MB --pool_ids='0,1;' \
                --sDMenable={mode} --fast_mode=0 --hash_lat=16 --enc_lat=16 --onchip_cache_size=4 --onchip_cache_lat=8 --dram_cache_size=16 \
                --cpu-type=TimingSimpleCPU \
                --cmd='{test_dir}/{binary_name}' > log-{binary_name}-{mode}.txt"
            process = multiprocessing.Process(target=execute_gem5_command, args=(gem5_command,))
            processes.append(process)
            process.start()
            print(f"Running {gem5_command}")

    for process in processes:
        process.join()
