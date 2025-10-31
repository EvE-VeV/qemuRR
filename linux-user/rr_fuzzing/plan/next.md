# RR-Fuzz 2.0: 最终实施蓝图

## 1. 最终目标与核心方法

-   **最终目标**: 发现目标程序中的高价值安全漏洞，包括内存安全问题、程序逻辑错误和状态机漏洞。
-   **核心方法**: **数据驱动的控制流诱导 (Data-Driven Control-Flow Inducement)**。我们不直接改变程序的执行序列，而是通过静态分析计算出精准的“数据诱饵”，在真实重放中注入这些数据，来“诱导”程序自己走进新的、未曾探索的代码路径，从而自然地产生全新的、100%有效的系统调用序列。

## 2. 最终架构图

```mermaid
graph TD
    subgraph "阶段1: 离线分析 (Offline Analysis)"
        A[目标二进制] --> C{静态分析引擎 (angr)};
        B[种子Trace池 (.dat + .bbl)] --> C;
        C -- "分析CFG, 求解新路径" --> D[生成“变异配方”库 (recipes.json)];
    end

    subgraph "阶段2 & 3: 在线Fuzzing闭环 (Online Fuzzing Loop)"
        B --> E{Conductor};
        D --> E;
        E -- "1. 选择种子和配方" --> F[启动QEMU];
        F -- "2. 执行目标导向的数据变异" --> G{程序真实执行};
        G -- "3. 记录Coverage & BB Trace" --> H{反馈与验证};
        H -- "发现新Coverage" --> I[捕获全新有效Trace];
        I --> B;
        G -- "发现崩溃" --> J[保存高质量崩溃用例];
    end
```

## 3. 详细的分阶段实施方案 (The Roadmap)

我们将严格按照以下四个阶段进行开发。每个阶段都有明确、具体、代码级的任务和交付成果。

---

### **阶段 0: 基础建设 - 动静态信息桥梁 (P0 - 关键依赖)**

**目标**: 让动态Trace信息丰富到足以指导静态分析。

**工作量**: 约5-7天

-   **任务 0.1: [C端] 记录基本块(BB)执行轨迹**
    -   **背景**: 仅有Syscall信息粒度太粗，无法与CFG精确匹配。
    -   **文件**: `accel/tcg/cpu-exec.c` (或等效的核心执行循环)
    -   **动作**: 在QEMU的翻译块(TB)执行循环中，添加一个helper函数`rr_trace_basic_block(tb->pc)`的调用。此函数会将TB的起始PC地址高效地写入一个与主trace关联的`.bbl` (Basic Block Log) 文件。
    -   **代码示例 (概念)**:
        ```c
        // cpu-exec.c
        cpu_loop_exec_tb(...) {
            // ...
            if (rr_is_tracing_enabled()) { // 新增的检查
                rr_trace_basic_block(tb->pc);
            }
            // ... 执行tb ...
        }
        ```

-   **任务 0.2: [Python端] 解析BB Trace**
    -   **文件**: `linux-user/rr_fuzzing/analysis/trace_analyzer.py`
    -   **动作**: 扩展`TraceAnalyzer`，使其能自动查找并解析`.bbl`文件，最终产出一个`[syscall_1, bb_1, bb_2, ..., syscall_2, ...]`的精确执行序列。

---

### **阶段 1: 核心引擎 - 离线路径分析与配方生成 (P0 - 核心功能)**

**目标**: 开发Fuzzer的“大脑”，一个能自动规划“攻击路线”的独立工具。

**工作量**: 约10-15天

-   **任务 1.1: [Python端] 创建`PathFinder`模块**
    -   **文件**: `linux-user/rr_fuzzing/analysis/path_finder.py` (新建)
    -   **依赖**: `pip install angr`
    -   **动作**: 实现一个主类`PathFinder`，接收“二进制文件”和“增强版trace”作为输入，使用`angr`加载二进制并构建CFG。

-   **任务 1.2: [Python端] 实现路径映射与分叉点识别**
    -   **文件**: `path_finder.py`
    -   **动作**: 将trace中的BB序列在CFG上“点亮”，标记为已覆盖路径。然后遍历所有已覆盖路径的邻居，找出所有未被覆盖的“分叉点”（新的代码分支）。

-   **任务 1.3: [Python端] 实现约束求解与“变异配方”生成**
    -   **文件**: `path_finder.py`
    -   **动作**:

        1.  对每个分叉点，调用`angr`的符号执行引擎求解出进入该分支所需满足的**路径约束**。
        2.  使用`angr`的**反向污点分析**，从约束中的变量开始向上回溯，直到找到其来源的系统调用（例如`syscall_index=25`的`read`）及其返回值/缓冲区。
        3.  将结果输出为`recipe.json`文件，格式如下：
            ```json
            {
              "target_branch": "0x4011ab",
              "required_mutation": {
                "syscall_index": 25,
                "type": "buffer_overwrite",
                "offset": 8,
                "size": 4,
                "data_template": "SOLVER_SOLUTION"
              }
            }
            ```


---

### **阶段 2: 执行引擎 - 目标导向的Fuzzing (P1 - 提升效果)**

**目标**: 让Fuzzer能够理解并精确执行“大脑”制定的计划。

**工作量**: 约7-10天

-   **任务 2.1: [C端] 增强Fuzzing指令的表达能力**
    -   **文件**: `linux-user/rr_fuzzing/core/rr_framework.h`
    -   **动作**: 扩展`FuzzInstruction`结构体，增加`uint32_t offset;`和`uint32_t size;`字段，并增加新的指令类型`FUZZ_CMD_OVERWRITE_AT_OFFSET`。

-   **任务 2.2: [C端] 实现精确变异指令**
    -   **文件**: `linux-user/rr_fuzzing/fuzzing/rr_fuzz_engine.c`
    -   **动作**: 在`rr_fuzz_mutate_syscall`中为`FUZZ_CMD_OVERWRITE_AT_OFFSET`实现逻辑：从`instr->data`中解析出具体数值，然后使用`memcpy`在`guest_memory_address + instr->offset`处覆写`instr->size`长度的数据。

-   **任务 2.3: [Python端] 改造Conductor以执行配方**
    -   **文件**: `linux-user/rr_fuzzing/fuzzing/fuzz_conductor.py`
    -   **动作**: 重写`SmartMutator.build_instructions()`函数。其新逻辑为：从`recipes.json`库中选择一个配方，然后根据配方的`required_mutation`内容，生成一个**精确的**、包含`offset`和`size`信息的`FuzzInstruction`。

---

### **阶段 3: 闭环与反馈 - Coverage与自我进化 (P1 - 关键能力)**

**目标**: 让Fuzzer拥有“眼睛”和“记忆”，实现自我进化。

**工作量**: 约10-12天

-   **任务 3.1: [C端] 实现Coverage TCG集成**
    -   **文件**: `accel/tcg/cpu-exec.c`, `linux-user/rr_fuzzing/core/rr_coverage.c`
    -   **动作**:

        1.  创建一个用于Coverage的**共享内存**。
        2.  在`cpu-exec.c`的TB执行循环中，添加hook，计算AFL风格的`(prev_pc >> 1) ^ cur_pc`边哈希。
        3.  以哈希为索引，在共享内存bitmap中对应的字节上加一。

-   **任务 3.2: [Python端] Conductor集成Coverage反馈**
    -   **文件**: `fuzz_conductor.py`
    -   **动作**: 每轮Fuzzing结束后，`FuzzConductor`读取Coverage共享内存，与一个全局bitmap对比，判断是否发现了**新的代码边**。

-   **任务 3.3: [C/Python端] 实现新种子捕获与管理**
    -   **动作 (C端)**: 需要一个机制，让Conductor可以通知QEMU的子进程：“你这次的执行很有价值，请将你的完整BB Trace和Syscall Trace记录下来”。这可以通过`FuzzSharedMemory`中的一个标志位实现。
    -   **动作 (Python端)**: 当`Conductor`在任务3.2中发现新Coverage时，它会设置上述标志位，并用同样的“配方”**再跑一次**。这次运行会生成一份全新的trace文件。`Conductor`会将其从临时目录移动到`seeds/`目录。
    -   **闭环**: Conductor的主循环和离线的`path_finder.py`都会从`seeds/`目录中读取和分析，从而形成进化。

---

## 4. 详细TODO清单与工作量

| ID | 任务描述 | 阶段 | 优先级 | 预估工作量 | 依赖 |

| :--- | :--- | :--- | :--- | :--- | :--- |

| **T0.1** | [C] 实现BB Trace记录模块 | 0 | **P0** | 2天 | - |

| **T0.2** | [C] 在TCG中添加BB Trace的hook | 0 | **P0** | 3天 | T0.1 |

| **T0.3** | [Py] 扩展TraceAnalyzer以解析BB Trace | 0 | **P0** | 1天 | T0.2 |

| **T1.1** | [Py] 创建PathFinder模块并集成angr | 1 | **P0** | 2天 | T0.3 |

| **T1.2** | [Py] 实现Trace到CFG的路径映射与分叉点识别 | 1 | **P0** | 4天 | T1.1 |

| **T1.3** | [Py] 实现符号执行与反向污点分析，生成配方 | 1 | **P0** | 7天 | T1.2 |

| **T2.1** | [C] 扩展FuzzInstruction结构体 | 2 | P1 | 1天 | - |

| **T2.2** | [C] 实现精确的内存覆写指令 | 2 | P1 | 3天 | T2.1 |

| **T2.3** | [Py] 改造Conductor为配方驱动模式 | 2 | P1 | 4天 | T1.3, T2.2 |

| **T3.1** | [C] 实现Coverage共享内存与TCG Hook | 3 | P1 | 5天 | - |

| **T3.2** | [Py] Conductor集成Coverage分析 | 3 | P1 | 2天 | T3.1 |

| **T3.3** | [C/Py] 实现新种子捕获与管理机制 | 3 | P1 | 4天 | T3.2 |

**总计预估**: **36-42个工作日**

这是一个宏大但分工明确、逻辑清晰、风险可控的计划。我们是否可以正式批准此最终方案，并授权开始实施第一项任务(T0.1)？