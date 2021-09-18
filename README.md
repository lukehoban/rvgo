# RISC-V emulator in Go

Linux running at ~2Mhz:

```
OpenSBI v0.8
   ____                    _____ ____ _____
  / __ \                  / ____|  _ \_   _|
 | |  | |_ __   ___ _ __ | (___ | |_) || |
 | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
 | |__| | |_) |  __/ | | |____) | |_) || |_
  \____/| .__/ \___|_| |_|_____/|____/_____|
        | |
        |_|

Platform Name       : riscv-virtio,qemu
Platform Features   : timer,mfdeleg
Platform HART Count : 1
Boot HART ID        : 0
Boot HART ISA       : rv64imafdcbnsu
BOOT HART Features  : pmp,scounteren,mcounteren,time
BOOT HART PMP Count : 16
Firmware Base       : 0x80000000
Firmware Size       : 96 KB
Runtime SBI Version : 0.2

MIDELEG : 0x0000000000000222
MEDELEG : 0x000000000000b109
PMP0    : 0x0000000080000000-0x000000008001ffff (A)
PMP1    : 0x0000000000000000-0xffffffffffffffff (A,R,W,X)
[    0.000000] OF: fdt: Ignoring memory range 0x80000000 - 0x80200000
[    0.000000] Linux version 5.4.0 (takahiro@takahiro-VirtualBox) (gcc version 10.1.0 (GCC)) #1 SMP Sun Oct 11 20:31:00 PDT 2020
[    0.000000] initrd not found or empty - disabling initrd
[    0.000000] Zone ranges:
[    0.000000]   DMA32    [mem 0x0000000080200000-0x0000000087ffffff]
[    0.000000]   Normal   empty
[    0.000000] Movable zone start for each node
[    0.000000] Early memory node ranges
[    0.000000]   node   0: [mem 0x0000000080200000-0x0000000087ffffff]
[    0.000000] Initmem setup node 0 [mem 0x0000000080200000-0x0000000087ffffff]
[    0.000000] software IO TLB: mapped [mem 0x83e3c000-0x87e3c000] (64MB)
[    0.000000] elf_hwcap is 0x112d
[    0.000000] percpu: Embedded 17 pages/cpu s30680 r8192 d30760 u69632
[    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 31815
[    0.000000] Kernel command line: root=/dev/vda rw ttyS0
[    0.000000] Dentry cache hash table entries: 16384 (order: 5, 131072 bytes, linear)
[    0.000000] Inode-cache hash table entries: 8192 (order: 4, 65536 bytes, linear)
[    0.000000] Sorting __ex_table...
[    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
[    0.000000] Memory: 51976K/129024K available (6166K kernel code, 387K rwdata, 1962K rodata, 213K init, 305K bss, 77048K reserved, 0K cma-reserved)
[    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=1, Nodes=1
[    0.000000] rcu: Hierarchical RCU implementation.
[    0.000000] rcu:     RCU restricting CPUs from NR_CPUS=8 to nr_cpu_ids=1.
[    0.000000] rcu: RCU calculated value of scheduler-enlistment delay is 25 jiffies.
[    0.000000] rcu: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=1
[    0.000000] NR_IRQS: 0, nr_irqs: 0, preallocated irqs: 0
[    0.000000] plic: mapped 53 interrupts with 1 handlers for 2 contexts.
[    0.000000] riscv_timer_init_dt: Registering clocksource cpuid [0] hartid [0]
[    0.000000] clocksource: riscv_clocksource: mask: 0xffffffffffffffff max_cycles: 0x24e6a1710, max_idle_ns: 440795202120 ns
[    0.000330] sched_clock: 64 bits at 10MHz, resolution 100ns, wraps every 4398046511100ns
[    0.006350] Console: colour dummy device 80x25
[    0.061158] printk: console [tty0] enabled
[    0.064907] Calibrating delay loop (skipped), value calculated using timer frequency.. 20.00 BogoMIPS (lpj=40000)
[    0.071021] pid_max: default: 32768 minimum: 301
[    0.080459] Mount-cache hash table entries: 512 (order: 0, 4096 bytes, linear)
[    0.086266] Mountpoint-cache hash table entries: 512 (order: 0, 4096 bytes, linear)
[    0.147251] rcu: Hierarchical SRCU implementation.
[    0.159109] smp: Bringing up secondary CPUs ...
[    0.162698] smp: Brought up 1 node, 1 CPU
[    0.176101] devtmpfs: initialized
[    0.214369] random: get_random_u32 called from bucket_table_alloc.isra.0+0x4e/0x154 with crng_init=0
[    0.229596] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645041785100000 ns
[    0.235644] futex hash table entries: 256 (order: 2, 16384 bytes, linear)
[    0.252619] NET: Registered protocol family 16
[    1.004435] vgaarb: loaded
[    1.023176] SCSI subsystem initialized
[    1.040987] usbcore: registered new interface driver usbfs
[    1.046258] usbcore: registered new interface driver hub
[    1.051057] usbcore: registered new device driver usb
[    1.085403] clocksource: Switched to clocksource riscv_clocksource
[    1.368901] NET: Registered protocol family 2
[    1.401444] tcp_listen_portaddr_hash hash table entries: 256 (order: 0, 4096 bytes, linear)
[    1.407649] TCP established hash table entries: 1024 (order: 1, 8192 bytes, linear)
[    1.414561] TCP bind hash table entries: 1024 (order: 2, 16384 bytes, linear)
[    1.419342] TCP: Hash tables configured (established 1024 bind 1024)
[    1.425572] UDP hash table entries: 256 (order: 1, 8192 bytes, linear)
[    1.430003] UDP-Lite hash table entries: 256 (order: 1, 8192 bytes, linear)
[    1.438657] NET: Registered protocol family 1
[    1.457454] RPC: Registered named UNIX socket transport module.
[    1.460850] RPC: Registered udp transport module.
[    1.463561] RPC: Registered tcp transport module.
[    1.466885] RPC: Registered tcp NFSv4.1 backchannel transport module.
[    1.470375] PCI: CLS 0 bytes, default 64
[    1.503201] workingset: timestamp_bits=62 max_order=14 bucket_order=0
[    2.030752] NFS: Registering the id_resolver key type
[    2.034478] Key type id_resolver registered
[    2.037728] Key type id_legacy registered
[    2.041286] nfs4filelayout_init: NFSv4 File Layout Driver Registering...
[    2.049276] 9p: Installing v9fs 9p2000 file system support
[    2.068910] NET: Registered protocol family 38
[    2.073114] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 253)
[    2.078607] io scheduler mq-deadline registered
[    2.081881] io scheduler kyber registered
[    3.816839] Serial: 8250/16550 driver, 4 ports, IRQ sharing disabled
[    3.869830] 10000000.uart: ttyS0 at MMIO 0x10000000 (irq = 10, base_baud = 230400) is a 16550A
[    8.348990] printk: console [ttyS0] enabled
[    8.431798] [drm] radeon kernel modesetting enabled.
[    8.724696] loop: module loaded
[    8.883840] virtio_blk virtio0: [vda] 204800 512-byte logical blocks (105 MB/100 MiB)
[    9.001852] libphy: Fixed MDIO Bus: probed
[    9.089842] e1000e: Intel(R) PRO/1000 Network Driver - 3.2.6-k
[    9.149054] e1000e: Copyright(c) 1999 - 2015 Intel Corporation.
[    9.213276] ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
[    9.272730] ehci-pci: EHCI PCI platform driver
[    9.333478] ehci-platform: EHCI generic platform driver
[    9.394449] ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
[    9.453573] ohci-pci: OHCI PCI platform driver
[    9.514010] ohci-platform: OHCI generic platform driver
[    9.581489] usbcore: registered new interface driver uas
[    9.642718] usbcore: registered new interface driver usb-storage
[    9.708040] mousedev: PS/2 mouse device common for all mice
[    9.786904] usbcore: registered new interface driver usbhid
[    9.846033] usbhid: USB HID core driver
[    9.951406] NET: Registered protocol family 10
[   10.039863] Segment Routing with IPv6
[   10.102449] sit: IPv6, IPv4 and MPLS over IPv4 tunneling driver
[   10.189783] NET: Registered protocol family 17
[   10.260784] 9pnet: Installing 9P2000 support
[   10.322578] Key type dns_resolver registered
[   10.423380] EXT4-fs (vda): mounting ext2 file system using the ext4 subsystem
[   10.536168] EXT4-fs (vda): warning: mounting unchecked fs, running e2fsck is recommended
[   10.613433] EXT4-fs (vda): mounted filesystem without journal. Opts: (null)
[   10.673739] VFS: Mounted root (ext2 filesystem) on device 254:0.
[   10.737193] devtmpfs: mounted
[   10.802606] Freeing unused kernel memory: 212K
[   10.861531] This architecture does not have kernel memory protection.
```