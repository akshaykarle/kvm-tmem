#ifndef _TMEM_H
#define _TMEM_H

#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/kvm_types.h>
#include <linux/kvm_para.h>
#include "tmem.h"

#define TMEM_SPEC_VERSION 1
#define TMEM_CLI	  1

/* Different tmem ops */
#define TMEM_CONTROL               0
#define TMEM_NEW_POOL              1
#define TMEM_DESTROY_POOL          2
#define TMEM_NEW_PAGE              3
#define TMEM_PUT_PAGE              4
#define TMEM_GET_PAGE              5
#define TMEM_FLUSH_PAGE            6
#define TMEM_FLUSH_OBJECT          7
#define TMEM_READ                  8
#define TMEM_WRITE                 9
#define TMEM_XCHG                 10

/* Bits for kvm_hypercall1(TMEM_NEW_POOL) */
#define TMEM_POOL_PERSIST          1
#define TMEM_POOL_SHARED           2
#define TMEM_POOL_PAGESIZE_SHIFT   4
#define TMEM_VERSION_SHIFT        24

/* flags for tmem_ops.new_pool */
#define TMEM_POOL_PERSIST          1
#define TMEM_POOL_SHARED           2

struct tmem_op {
        uint32_t cmd;
        int32_t pool_id;
        union {
                struct {  /* for cmd == TMEM_NEW_POOL */
                        uint16_t cli_id;
                        uint32_t flags;
                } new;
                struct {
                        uint64_t oid[3];
                        uint32_t index;
                        uint32_t tmem_offset;
                        uint32_t pfn_offset;
                        uint32_t pfn;
                        uint32_t len;
			uint16_t cli_id;
                } gen;
        } u;
};
#endif
