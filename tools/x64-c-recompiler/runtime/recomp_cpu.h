#pragma once

#include <stdint.h>

typedef struct RecompXmm {
    uint64_t lanes[2];
} RecompXmm;

typedef struct RecompCpu {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    RecompXmm xmm[16];
    uint64_t rip;
    uint64_t image_base;
    int cf;
    int of;
    int sf;
    int zf;
    int pf;
    int af;
    uint64_t tls_base;
} RecompCpu;

typedef void (*RecompCpuFunction)(RecompCpu *cpu);

void recomp_cpu_dispatch(RecompCpu *cpu, uint64_t target);
void recomp_cpu_trap(RecompCpu *cpu, uint64_t address);
