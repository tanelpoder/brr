Other than the default **brr** TUI (also available as **brr top**), you can get
regular tabular CLI output too, including JSON and CSV. Use **brr list** for the
canonical loaded-program listing command.

List top eBPF program runtime/overhead, program executions/s and avg program/probe run in nanoseconds:

```
$ sudo brr activity

 ID  TYPE        NAME             CPU%     EXECS/s  AVG_NS  NS_PER/s   XLAT_B  JIT_B
206  tracepoint  raw_syscalls__s  19.8829  1516573     131  198829397     392    234
205  tracepoint  raw_syscalls__s  19.1351  1516524     126  191350855     112     73
177  tracing     xcap_sys_enter   18.6948  1516537     123  186947636     496    338
174  tracing     get_tasks         8.2631   173190     477   82630615   52800  38147
178  tracing     xcap_sys_exit     8.0269  1516583      52   80268842    1384    928
181  tracing     xcap_iorq_issue   1.0998    83264     132   10997533     552    317
182  tracing     xcap_iorq_compl   0.8170    83264      98    8170407    1448    779
180  tracing     xcap_iorq_inser   0.0044      112     388      43566     424    250
```

Just like the `brr top` "p" - profile command in TUI, you can run `brr profile` for drilling down into which eBPF program lines were most active. This relies on whatever perf events are available on your platform/VM (like hardware PMU CPU "cycles" vs software timer based "cpu-clock"). You can list the available perf events using `brr perf-events` (defaults to HW CPU "cycles" when available):

The profiler continuously polls and drains its per-CPU perf rings. It prints a
capture summary with the automatically selected pages per CPU, drain interval,
peak ring occupancy, and perf running percentage. Any kernel-reported loss,
throttling, ring overrun, malformed record, or multiplexing is called out as an
incomplete profile. Use `--fail-on-loss` in automation to make an incomplete
capture exit with status 1, or override the automatic sizing with
`--perf-buffer-pages` and `--perf-drain-ms`.

For tiny, frequently executed BPF programs, a five-second 997 Hz profile may be
healthy but still contain too few BPF samples for a stable source-line ranking.
Prefer `cycles` at a higher supported frequency and a longer duration for
hotspot work. Add `--kernel-samples` when helper and kernel functions called by
the BPF program are part of the CPU cost you want to measure. The direct and
inclusive views answer different questions; helper samples are intentionally
absent from the direct view.

```
$ sudo brr profile

 ID  TYPE        NAME             CPU%  
206  tracepoint  raw_syscalls__s  1.0231
177  tracing     xcap_sys_enter   0.4012
178  tracing     xcap_sys_exit    0.3611
205  tracepoint  raw_syscalls__s  0.3611
174  tracing     get_tasks        0.3009

Breakdown of program 206 (raw_syscalls__s):

CPU%    FILE    LINE  SOURCE                                                                           
0.5015  main.c   127          lock_xadd(&val->count, 1);                                               
0.2407  main.c    77      u64 pid_tgid = bpf_get_current_pid_tgid();                                   
0.2207  main.c   138  }                                                                                
0.0401  main.c   114      u32 key = pid_tgid >> 32;                                                    
0.0201  main.c   121      u64 *start_ns = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -1), &pid_tgid);

Breakdown of program 177 (xcap_sys_enter):

CPU%    FILE           LINE  SOURCE                                                                                        
0.1204  syscall.bpf.c   227  int BPF_PROG(xcap_sys_enter, struct pt_regs *regs, long syscall_nr)                           
0.0602  syscall.bpf.c   239      storage->state.in_syscall_nr = syscall_nr;                                                
0.0602  syscall.bpf.c   240      storage->state.sc_sequence_num++;                                                         
0.0401  syscall.bpf.c   227  int BPF_PROG(xcap_sys_enter, struct pt_regs *regs, long syscall_nr)                           
0.0401  syscall.bpf.c   234      storage = bpf_task_storage_get(&task_storage, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);

Breakdown of program 178 (xcap_sys_exit):

CPU%    FILE           LINE  SOURCE                                                     
0.2207  syscall.bpf.c   270  int BPF_PROG(xcap_sys_exit, struct pt_regs *regs, long ret)
0.0401  syscall.bpf.c   279      bool sc_was_sampled = storage->state.sc_sampled;       
0.0201  syscall.bpf.c   219      storage->state.trace_payload_len = 0;                  
0.0201  syscall.bpf.c   270  int BPF_PROG(xcap_sys_exit, struct pt_regs *regs, long ret)
0.0201  syscall.bpf.c   273      struct task_struct *task = bpf_get_current_task_btf(); 

Breakdown of program 205 (raw_syscalls__s):

CPU%    FILE    LINE  SOURCE                                        
0.2808  main.c    37      u64 pid_tgid = bpf_get_current_pid_tgid();
0.0602  main.c    63      u64 t = bpf_ktime_get_ns();               
0.0201  main.c    65      return 0;                                 

Breakdown of program 174 (get_tasks):

CPU%    FILE        LINE  SOURCE                                                                                              
0.1003  task.bpf.c   233              __s64 orig_ax = (__s64) passive_regs->orig_ax;                                          
0.0401  task.bpf.c   379                                           storage->cache.ufunc_depth > 0);                           
0.0201  task.bpf.c     -  -                                                                                                   
0.0201  task.bpf.c   202      if (xcap_dump_kernel_stack_traces || xcap_dump_user_stack_traces) {                             
0.0201  task.bpf.c   274      else if ((passive_syscall_nr == __NR_io_getevents || passive_syscall_nr == __NR_io_pgetevents ||
```
The above profile only reports CPU samples falling into eBPF programs, but in reality, eBPF programs call separate helper functions that are part of the kernel and may even trigger other things like pagefault handlers etc (sleepable eBPF programs). The `--kernel-samples` option will act more like `perf record -g` option, walking up the stack callgraph of any kernel function and checking if its parent/ancestor caller is an eBPF program (if yes, account this sample).

The `brr top` TUI automatically captures kernel functions beneath the selected
eBPF program. A `+` in front of an eBPF code line indicates collapsed
helper/kernel activity; use `e` and `c` to expand and collapse it. The compact
header reports total sampled CPU (where 100% is one fully busy CPU) and splits
it into all direct eBPF code, activity under eBPF, and only a genuine inclusive
attribution mismatch. The `SAMPLES` and `%THIS` columns use non-overlapping
leaves and total exactly 100.00%. Detailed rows hidden by `--line-limit` or
`--source-limit` remain attributed in `Other eBPF` and `Other under-eBPF` rows;
they are never reported as unaccounted. Samples without source metadata also
retain their known direct or under-eBPF CPU attribution.

Textmode drilldowns show expanded helper/kernel children by default. Use
`brr top --textmode --profile-top --collapse-samples` to fold child activity
into its calling eBPF rows. Standalone profiles and profiled textmode default to
the top ten detailed hotspots and add exact `Other` totals. The interactive TUI
defaults to unlimited hotspots so no sampled detail is hidden; pass an explicit
`--line-limit` value to override either default.

```
$ sudo brr profile --kernel-samples
 ID  TYPE        NAME             KERNEL_SAMPLES  INCL_SAMPLES  CPU%    KERNEL_CPU%  INCL_CPU%
174  tracing     get_tasks                    21  26            0.1003       0.4213  0.5216   
206  tracepoint  raw_syscalls__s              17  25            0.1605       0.3410  0.5015   
177  tracing     xcap_sys_enter               17  24            0.1404       0.3410  0.4814   
205  tracepoint  raw_syscalls__s              20  23            0.0602       0.4012  0.4614   
178  tracing     xcap_sys_exit                 5  7             0.0401       0.1003  0.1404   
181  tracing     xcap_iorq_issue               1  1             0.0000       0.0201  0.0201   

Breakdown of program 174 (get_tasks):

CPU%    FILE        LINE  SOURCE                                                                   
0.0401  task.bpf.c   379                                           storage->cache.ufunc_depth > 0);
0.0201  task.bpf.c   233              __s64 orig_ax = (__s64) passive_regs->orig_ax;               
0.0201  task.bpf.c   261      if (passive_syscall_nr == __NR_ppoll && passive_regs) {              
0.0201  task.bpf.c   281          ctx_id = passive_regs->di;                                       

Kernel/helper samples for program 174 (get_tasks):

CPU%    KIND        SYMBOL                 MODULE  BPF_FILE    BPF_LINE  BPF_SOURCE                                                                              
0.0401  kernel      __pi_memcpy            -       task.bpf.c       804                          if (xcap_copy_from_user_task(&next_fp, sizeof(next_fp),         
0.0401  bpf_helper  bpf_task_storage_get   -       task.bpf.c       189      if (!storage)                                                                       
0.0401  kernel      read_tsc               -       task.bpf.c       254      sync_passive_syscall_state(&storage->state, passive_syscall_nr, bpf_ktime_get_ns());
0.0201  kernel      __get_user_pages       -       task.bpf.c       804                          if (xcap_copy_from_user_task(&next_fp, sizeof(next_fp),         
0.0201  bpf_map     __pte_offset_map_lock  -       task.bpf.c       808                          if (xcap_copy_from_user_task(&ret_addr, sizeof(ret_addr),       

Breakdown of program 206 (raw_syscalls__s):

CPU%    FILE    LINE  SOURCE                                        
0.1204  main.c   127          lock_xadd(&val->count, 1);            
0.0201  main.c    77      u64 pid_tgid = bpf_get_current_pid_tgid();
0.0201  main.c   114      u32 key = pid_tgid >> 32;                 

Kernel/helper samples for program 206 (raw_syscalls__s):

CPU%    KIND     SYMBOL                            MODULE  BPF_FILE   BPF_LINE  BPF_SOURCE                                                                       
0.1404  kernel   read_tsc                          -       main.c          128          lock_xadd(&val->total_ns, bpf_ktime_get_ns() - *start_ns);               
0.0401  kernel   lookup_nulls_elem_raw             -       helpers.h      1227    return bpf_map_lookup_elem((void *)map, key);                                  
0.0201  kernel   blk_complete_request.constprop.0  -       main.c           77      u64 pid_tgid = bpf_get_current_pid_tgid();                                   
0.0201  bpf_map  htab_map_hash                     -       main.c          121      u64 *start_ns = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -1), &pid_tgid);
0.0201  bpf_map  htab_map_hash                     -       main.c          121      u64 *start_ns = bpf_map_lookup_elem((void *)bpf_pseudo_fd(1, -1), &pid_tgid);

Breakdown of program 177 (xcap_sys_enter):

CPU%    FILE           LINE  SOURCE                                                                        
0.0602  syscall.bpf.c   227  int BPF_PROG(xcap_sys_enter, struct pt_regs *regs, long syscall_nr)           
0.0201  syscall.bpf.c   200      __u32 head = 0, tail = 0;                                                 
0.0201  syscall.bpf.c   230      struct task_struct *task = bpf_get_current_task_btf();                    
0.0201  syscall.bpf.c   238      storage->state.sc_enter_time = bpf_ktime_get_ns();                        
0.0201  syscall.bpf.c   242      if (syscall_nr == __NR_io_getevents || syscall_nr == __NR_io_pgetevents) {

Kernel/helper samples for program 177 (xcap_sys_enter):

CPU%    KIND        SYMBOL                      MODULE  BPF_FILE       BPF_LINE  BPF_SOURCE                                                                                    
0.0802  kernel      read_tsc                    -       syscall.bpf.c       238      storage->state.sc_enter_time = bpf_ktime_get_ns();                                        
0.0602  kernel      copy_from_user_nofault      -       syscall.bpf.c       203      if (BPF_CORE_READ_USER_INTO(&head, ring, head)) return -1;                                
0.0201  bpf_helper  bpf_probe_read_user         -       syscall.bpf.c       203      if (BPF_CORE_READ_USER_INTO(&head, ring, head)) return -1;                                
0.0201  bpf_helper  bpf_task_storage_get_recur  -       syscall.bpf.c       234      storage = bpf_task_storage_get(&task_storage, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
0.0201  kernel      check_heap_object           -       syscall.bpf.c       204      if (BPF_CORE_READ_USER_INTO(&tail, ring, tail)) return -2;                                

Breakdown of program 205 (raw_syscalls__s):

CPU%    FILE    LINE  SOURCE                                        
0.0401  main.c    37      u64 pid_tgid = bpf_get_current_pid_tgid();
0.0201  main.c    63      u64 t = bpf_ktime_get_ns();               

Kernel/helper samples for program 205 (raw_syscalls__s):

CPU%    KIND        SYMBOL           MODULE  BPF_FILE  BPF_LINE  BPF_SOURCE                     
0.0802  kernel      read_tsc         -       main.c          63      u64 t = bpf_ktime_get_ns();
0.0401  kernel      __pi_memcpy      -       main.c          65      return 0;                  
0.0401  kernel      alloc_htab_elem  -       main.c          65      return 0;                  
0.0201  bpf_helper  bpf_obj_memcpy   -       main.c          65      return 0;                  
0.0201  bpf_helper  bpf_obj_memcpy   -       main.c          65      return 0;                  

Breakdown of program 178 (xcap_sys_exit):

CPU%    FILE           LINE  SOURCE                                                     
0.0201  syscall.bpf.c   270  int BPF_PROG(xcap_sys_exit, struct pt_regs *regs, long ret)
0.0201  syscall.bpf.c   334          storage->state.trace_payload_len = 0;              

Kernel/helper samples for program 178 (xcap_sys_exit):

CPU%    KIND        SYMBOL                      MODULE  BPF_FILE       BPF_LINE  BPF_SOURCE                                                   
0.0401  bpf_helper  bpf_task_storage_get_recur  -       syscall.bpf.c       274      storage = bpf_task_storage_get(&task_storage, task, NULL,
0.0201  bpf_helper  bpf_task_storage_get_recur  -       syscall.bpf.c       274      storage = bpf_task_storage_get(&task_storage, task, NULL,
0.0201  bpf_helper  bpf_task_storage_get_recur  -       syscall.bpf.c       274      storage = bpf_task_storage_get(&task_storage, task, NULL,
0.0201  bpf_helper  bpf_task_storage_get_recur  -       syscall.bpf.c       274      storage = bpf_task_storage_get(&task_storage, task, NULL,

Kernel/helper samples for program 181 (xcap_iorq_issue):

CPU%    KIND    SYMBOL            MODULE  BPF_FILE            BPF_LINE  BPF_SOURCE                                                              
0.0201  kernel  htab_lock_bucket  -       iorq_hashmap.bpf.c        56          if (bpf_map_update_elem(&iorq_tracking, &rq, &ni, BPF_ANY) != 0)
```
I haven't put much thought under these CLI text reports yet, like how to add up and report Linux kernel function usage nested under eBPF programs. The `brr top` output is probably easier to navigate for now. For automation and agents, you can use `--json` or `--csv` options.
