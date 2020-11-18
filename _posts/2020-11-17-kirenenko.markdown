---
layout: post
title:  "Kirenenko: Dynamic Symbolic Execution as Taint Analysis"
date:   2020-11-17 19:00:00 -0800
categories: fuzzing
---

## The Story

In the second half of the year 2017, [Byoungyoung](https://lifeasageek.github.io/)
and I were discussing how we can make fuzzing more efficient at flipping conditional
branches. He suggested we could use dynamic taint analysis to find input bytes
that will affect a target branch so we can focus on mutating a smaller set of
bytes instead of the whole input. One challenge we're facing, however, is how to
further improve the efficiency of finding a satisfying assignment to those bytes
so we can flip the branch. One idea we thought about is to get a bunch of
input/output pairs and leverage the universal approximation theorem of deep neural
network (DNN) to train a model (specific to the target branch); then we can use this
model to find the satisfying input. At that time, I was reading some papers on
program synthesis and learned that this idea may not work very well because
(1) the neural network may not be able to approximate complex branch constraints,
(2) even if it can approximate, training the model may require many input/output pairs, and
(3) the trained model usually cannot be used to solve other branches.
Instead, I suggest we could use those input/output pairs to *synthesize* the
symbolic formula of the branch constraints then ask SMT solvers to solve it.
This is inspired by some research at that time
(e.g., [DeepCoder](https://www.microsoft.com/en-us/research/publication/deepcoder-learning-write-programs/)),
which suggests that if we want to approximate an unknown function `f` based on
some input/output pairs, it's probably a better idea to use machine learning to
guide the synthesis of an approximation function `f'` that can generate the same
set of input/output pairs than to directly approximate `f` using a DNN.
So we started building [SynFuzz](https://arxiv.org/abs/1905.09532).
Unfortunately, we didn't manage to publish SynFuzz as many taint-guided fuzzers
were released, including [Angora](https://github.com/AngoraFuzzer/Angora) and
[RedQueen](https://github.com/RUB-SysSec/redqueen).

However, when we were preparing the resubmission of the paper in the summer of 2019,
I realize we can actually trace the full symbolic formula using the same taint analysis
framework thus avoid the cumbersome synthesis process.
More importantly, this actually resulted in a very promising dynamic symbolic
execution engine because

- The symbolic formulas are collected at a similar speed of taint analysis,
  which is much faster than previous interpretation-based approaches like
  [KLEE](https://klee.github.io/) and [angr](https://angr.io/).

- The symbolic formulas are collected at the LLVM IR level, so they're simpler
  than those collected at binary level and [easier to solve](http://www.s3.eurecom.fr/docs/acsac19_poeplau.pdf).

In this blog post, I'm going to explain some technical details of
[Kirenenko](https://github.com/ChengyuSong/Kirenenko).

Since the implementation is quite simple
(a small modification over the data-flow sanitizer from LLVM),
I didn't thought it would be worth writing a paper for it.
So I just open-soured the code
and hope people would build more interesting tools based on it.

### Problem Formulation

#### Background: Dynamic Data-Flow Analysis

Dynamic data-flow analysis aims to track additional properties of
program variables according to its runtime data and control dependencies.
To facilitate this, an analysis framework associates each program variable
with a label (a.k.a., metadata) which represents its properties.
A particular dynamic data-flow flow analysis needs to define four policies:

- **Label interpretation** defines what properties are being tracked.
  Typical interpretations include whether the data is trustworthy and
  whether the data contain sensitive (e.g., personal health) data.

- **Label sources** define where a non-default label is introduced.
  Examples include APIs where the test, untrusted, or sensitive data is read.

- **Label propagation** defines how different labels are combined or
  transformed by an executed instruction.
  For example, when tracking the propagation of untrusted input data from the internet,
  a combination of an untrusted label with any other label always ends up with an untrusted label.

- **Lebel sinks** define where and how the additional runtime properties are used.
  For example, a policy to detect privacy data leakage would check data that leaves
  the local host (e.g., sent to the network) to ensure its label is not sensitive.

One of the most common form of dynamic data-flow analysis used in security is
dynamic taint analysis, where we have two labels: `tainted` and `untainted`.
As mentioned above, `tainted` could mean untrustworthy, like data from the network
or the user space; it could also mean sensitive information.
Dynamic taint analysis has been used in so many security applications that I'm
not going to enumerate.

#### Background: Dynamic Symbolic Execution

Symbolic execution treat program inputs as symbolic values instead of concrete values.
Program variables (including memory and register content)
can then be represented as symbolic expressions.
A symbolic execution engine maintains (1) a symbolic state,
which maps program variables to their symbolic expressions, and
(2) a set of path constraints, which is a quantifier-free
first-order formula over symbolic expressions.
To generate a concrete input that would allow the program to follow
the same execution trace, the symbolic execution engine uses path constraints to
query an SMT solver for satisfiability and feasible assignment to
symbolic values (i.e., input bytes).

#### Observation: Formula Construction as Data-Flow Analysis

If we think carefully, we can see that maintaining the symbolic state
is a special form of dynamic data-flow analysis:

- Label interpretation: in symbolic execution, the label of a variable is its
  symbolic expression.

- Label source: in test case generation, we mark input bytes as symbolic.

- Label propagation: when labels (symbolic expressions) merge, we create a
  new expression that combines the "results" according to the operation.
  If the expression is stored as abstracted syntax tree (AST), then merging
  means creating a new AST node with the operand ASTs as child nodes.

- Label sink: at conditional branches (or other interesting places), we use
  the collected symbolic expressions to consult an SMT solver if certain
  constraints are feasible (e.g., if the branch condition can be evaluated to
  `true`); if so, request a model (assignments).

Kirenenko is built based on this observation.

### Technical Details

#### Background: DFSan

Kirenenko is built upon the [DataFlowSanitizer](https://clang.llvm.org/docs/DataFlowSanitizer.html)
(DFSan) from the LLVM project.
DFSan is a byte-granularity dynamic data-flow analysis framework.
It performs source code (actually IR) level instrumentation to track runtime data-flow.
This is done at two levels.
For data in LLVM registers (IR values), it uses shadow registers to store the labels.
For data in memory, it uses the highly optimized shadow memory to map each memory
byte to its corresponding label in the shadow memory.
The most attractive design of DFSan, when compared with other dynamic taint analysis
frameworks is that DFSan does not store any information in the label itself.
Instead, the labels are indices into another metadata structure called `union table`,
which stores the real input dependencies.
Moreover, to track the data-flow at byte-granularity,
the union table is already structured as trees:
*when merging two labels (i.e., two sets of input dependencies),
DFSan will allocate a new label (union table entry) and assign the two labels
as child nodes.

```cpp
struct dfsan_label_info {
  dfsan_label l1;
  dfsan_label l2;
  const char *desc;
  void *userdata;
};

dfsan_label __dfsan_union(dfsan_label l1, dfsan_label l2) {
  // simplified
  dfsan_label label =
    atomic_fetch_add(&__dfsan_last_label, 1, memory_order_relaxed) + 1;
  __dfsan_label_info[label].l1 = l1;
  __dfsan_label_info[label].l2 = l2;
  return label;
}
```

Note that the whole union table is allocated during initialization as a big
array so allocating a new entry is very cheap, just an `atomic_fetch_add`.

#### Extending the Union Table

Following our problem formulation, it is kind of straightforward to see that to
track symbolic expressions, instead of just input dependencies, we can just
extend the union table entry to an AST node and track more information when
merging two labels (two sub-expressions).

```cpp
struct dfsan_label_info {
  dfsan_label l1; // symbolic sub-expression, 0 if the operand is concrete
  dfsan_label l2; // symbolic sub-expression, 0 if the operand is concrete
  u64 op1;        // concrete operand, 0 if the operand is symbolic
  u64 op2;        // concrete operand, 0 if the operand is symbolic
  u16 op;         // the operation of the node, using LLVM IR operations
  u16 size;       // size of the result
};

dfsan_label __taint_union(dfsan_label l1, dfsan_label l2, u16 op, u16 size,
                          u64 op1, u64 op2) {
  // omitted  
}
```

Conceptually, as simple as this. Of course, we need additional modifications to
the instrumentation [pass](https://github.com/ChengyuSong/Kirenenko/blob/master/llvm_mode/pass/TaintPass.cc)
so we can track additional information.
We also need to modify how `load` and `store` are handled:
when storing an expression larger than one byte,
we need to break it down using the `extract` operation;
and when loading an expression larger than one byte,
we need to `cancat` the sub-expressions.
Finally, we also need to add a hash table to deduplicate the symbolic expression
so they won't blow up the union table.

#### Generating New Test Inputs

To generate new test inputs, we instrumented conditional `branch` instructions and
`switch` instructions (i.e., LLVM IR instructions) to invoke a callback function
in the runtime.
Inside the callback function, we will traverse the union table entry (i.e., walk
the AST) to translate the LLVM IR level AST to Z3 AST, then consult the Z3 SMT
solver to check the feasibility of a branch target; if so, we get the model and
generate a new input.
For this step, we follow what [QSYM](https://github.com/sslab-gatech/qsym) does:
track nested branches and if the nested branch solving fails, do optimistic solving.

#### External Libraries

The biggest limitation of Kirenenko is its support for third party libraries,
which is inherits from DFSan.
Specifically, DFSan performs source code (IR) level instrumentation so it cannot
propagate data-flow for dynamic libraries that are instrumented.
One example is `libc`.
To support those libraries, we either need to create wrapper functions to specify
how data-flow should be propagated (take a look at
[`dfsan_custom.cc`](https://github.com/ChengyuSong/Kirenenko/blob/master/llvm_mode/dfsan_rt/dfsan/dfsan_custom.cc))
or compile the library with instrumentations.
While other source-code-based symbolic execution tools like KLEE and SymCC also
face the same problem, it indeed makes it less convenient than binary-based tools
like QSYM.

### Performance

Kirenenko is fast for three reasons:

1. The symbolic constraints collection is done at native speed, or use
   [SymCC](https://github.com/eurecom-s3/symcc/)'s term, compilation-based,
   instead of interpretation-based.

2. The symbolic constraints are collected at LLVM IR level so they are simpler
   and faster to solve, as shown in the evaluation of SymCC.

3. It is built upon the highly optimized sanitizer infrastructure: accessing
   the label is fast, access each AST node is fast, and allocation of each
   AST node is also fast.

So how fast it really is? Here are some quick test results I got, please feel
free to grade the code and try yourself.

Program | Native  | w/o Solving | w/ Solving
:-------| ------: | -----------:| ---------:
objdump | 0.0009s | 0.2665s     | 3.5206s
size    | 1.0010s | 0.2461s     | 3.3909s
readelf | 0.0009s | 0.4068s     | 4.9730s
tcmpdump| 0.0030s | 0.0090s     | 0.8770s
readpng | 0.0010s | 0.0060s     | 90.775s


As we can see, although it's still much slower than native execution,
collecting the symbolic constraints itself is very fast now and the bottleneck
is on constraint solving.
I didn't include the numbers for QSYM and SymCC, if you're interested, you can
test yourself.

Here are some [FuzzBench](https://github.com/google/FuzzBench)
results when pairing Kirenenko with [AFL++](https://github.com/AFLplusplus/AFLplusplus).

![libjpeg-coverage]({{ site.url }}/data/libjpeg-turbo-07-2017_coverage_growth.svg)
![libjpeg-pairwise]({{ site.url }}/data/libjpeg-turbo-07-2017_pairwise_unique_coverage_plot.svg)
![libpng-coverage]({{ site.url }}/data/libpng-1.2.56_coverage_growth.svg)
![libpng-pairwise]({{ site.url }}/data/libpng-1.2.56_pairwise_unique_coverage_plot.svg)
![sqlite-coverage]({{ site.url }}/data/sqlite3_ossfuzz_coverage_growth.svg)
![sqlite-pairwise]({{ site.url }}/data/sqlite3_ossfuzz_pairwise_unique_coverage_plot.svg)
