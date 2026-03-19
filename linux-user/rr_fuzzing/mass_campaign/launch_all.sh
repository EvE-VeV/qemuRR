#!/bin/bash
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_squashfs-root-0.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_squashfs-root.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_squashfs-root.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_sim_root.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_rootfs.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_rootfs.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_rootfs_ubifs.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_rootfs_ubifs.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_rootfs_ubifs.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_rootfs_ubifs.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_squashfs-root.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_sim_root.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_squashfs-root-0.sh &
sleep 0.5; /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/mass_campaign/run_fuzz_squashfs-root.sh &
echo '[*] All targets launched.'
wait
