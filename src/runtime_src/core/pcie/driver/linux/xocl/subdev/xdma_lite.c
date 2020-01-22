/*
 * Copyright (C) 2020 Xilinx, Inc. All rights reserved.
 *
 * Authors: Max Zhen <maxz@xilinx.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/eventfd.h>
#include <linux/fs.h>
#include "../xocl_drv.h"

#define	XDMAL_ERR(xl, fmt, arg...)  xocl_err(&xl->xl_pdev->dev, fmt, ##arg)
#define	XDMAL_WARN(xl, fmt, arg...) xocl_warn(&xl->xl_pdev->dev, fmt, ##arg)
#define	XDMAL_INFO(xl, fmt, arg...) xocl_info(&xl->xl_pdev->dev, fmt, ##arg)
#define	XDMAL_DBG(xl, fmt, arg...)  xocl_dbg(&xl->xl_pdev->dev, fmt, ##arg)

#define	SPC_LEFT(total, used)	((used) >= (total) ? 0 : (total) - (used))
#define	XDMAL_SNPRT(buf, total, used, fmt, arg...)	\
	scnprintf((buf) + (used), SPC_LEFT(total, used), fmt, ##arg)

#define	XDMAL_PCIDEV(xl)	(XDEV(xocl_get_xdev((xl)->xl_pdev))->pdev)
#define	XDMAL_REG_GRP_OFFSET(grp, eng)	(((grp) << 12) | ((eng) << 8))
#define	XDMAL_IDENTIFIER	(0x1fc)
#define	XDMAL_MAX_DMA_ENG	4
#define	XDMAL_MAX_DMA_INTR	(XDMAL_MAX_DMA_ENG * 2)
#define	XDMAL_MAX_USER_INTR	8
#define	XDMAL_MAX_INTR		(XDMAL_MAX_USER_INTR + XDMAL_MAX_DMA_INTR)
#define XDMAL_PAGE_OFFSET(addr)	((u64)(addr) & (PAGE_SIZE - 1))
#define XDMAL_NUM_PAGES(addr, size)	\
	(PAGE_ALIGN(XDMAL_PAGE_OFFSET(addr) + (size)) >>  PAGE_SHIFT)
#define	XDMAL_MAX_DESC_BUF_SIZE	(2 * 1024 * 1024)
#define	XDMA_LITE_NUM_DESC(len)	((len) / sizeof(xdma_lite_desc_t))
#define	XDMAL_MAX_DESCS		XDMA_LITE_NUM_DESC(XDMAL_MAX_DESC_BUF_SIZE)
/* maximum size of a single DMA transfer descriptor */
#define XDMA_LITE_DESC_BLEN_MAX	((1UL << (28)) - 1)
#define	XDMA_LITE_DESC_MAX_ADJ	0xf

typedef struct xdma_lite_reg_addr_fmt {
	union {
		struct {
			u64 xlraf_offset:8;
			u64 xlraf_chan:4;
			u64 xlraf_tgt:4;
			u64 xlraf_rsvd:48;
		};
		u64 xlraf_val;
	};
} xdma_lite_reg_addr_fmt_t;

enum xdma_lite_reg_grps {
	XLRG_H2C_CHAN = 0,
	XLRG_C2H_CHAN = 1,
	XLRG_INTR = 2,
	XLRG_CONFIG = 3,
	XLRG_H2C_SG = 4,
	XLRG_C2H_SG = 5,
};

typedef union xdma_lite_identifier {
	struct {
		u32 xli_ver:8;
		u32 xli_id:4;		/* only valid for chan regs */
		u32 xli_reserved:3;	/* only valid for chan regs */
		u32 xli_is_stream:1;	/* only valid for chan regs */
		u32 xli_xdma_grp:4;
		u32 xli_xdma_magic:12;
	};
	u32 xli_value;
} xdma_lite_identifier_t;

typedef struct xdma_lite_desc {
	union {
		struct {
			u32 xld_stop:1;
			u32 xld_completed:1;
			u32 xld_resvd1:6;
			u32 xld_next_adj:6;
			u32 xld_resvd2:2;
			u32 xld_magic:16;
		};
		u32 xld_control;
	};
	u32 xld_bytes;		/* transfer length in bytes */
	u32 xld_src_addr_lo;	/* source address (low 32-bit) */
	u32 xld_src_addr_hi;	/* source address (high 32-bit) */
	u32 xld_dst_addr_lo;	/* destination address (low 32-bit) */
	u32 xld_dst_addr_hi;	/* destination address (high 32-bit) */
	/*
	 * next descriptor in the single-linked list of descriptors;
	 * this is the PCIe (bus) address of the next descriptor in the
	 * root complex memory
	 */
	u32 xld_next_lo;	/* next desc address (low 32-bit) */
	u32 xld_next_hi;	/* next desc address (high 32-bit) */
} __packed xdma_lite_desc_t;

typedef struct xdma_lite_io_req {
	struct list_head xlir_list;
	struct xdma_lite *xlir_xl;

	/* Src/tgt buffer. */
	char __user *xlir_usr_addr;
	u64 xlir_ep_addr;
	size_t xlir_size;

	/* Page list. */
	struct page **xlir_pages;
	size_t xlir_npages;

	/* S/G table. */
	struct sg_table xlir_sgt;

	/* Descriptor list. */
	xdma_lite_desc_t *xlir_descs;
	dma_addr_t xlir_descs_bus_addr;
	size_t xlir_descs_total_len;

	/* IO direction. */
	bool xlir_write;
	/* DMA engine associated. */
	struct xdma_lite_engine *xlir_engine;
	/* Number of descriptors for current xfer. */
	size_t xlir_ndescs;
	/* Descriptor list for next xfer should start from below position. */
	struct scatterlist *xlir_curr_sg; /* next sg to start w/ */
	size_t xlir_curr_sg_offset; /* offset into next sg */
	size_t xlir_curr_bytes; /* offset into device buffer */

	struct completion xlir_comp;
	int xlir_err;
	struct work_struct xlir_work;

	/* Debug dump msg helpers. */
	size_t xlir_sg_dump_ent;
	size_t xlir_desc_dump_ent;
} xdma_lite_io_req_t;

typedef	union xdma_lite_chan_ctrl_status {
	struct {
		u32 xlec_run:1;
		u32 xlec_ie_desc_stopped:1;
		u32 xlec_ie_desc_completed:1;
		u32 xlec_ie_align_mismatch:1;
		u32 xlec_ie_magic_stopped:1;
		u32 xlec_ie_invalid_length:1;
		u32 xlec_ie_idle_stopped:1;
		u32 xlec_reserved1:2;
		u32 xlec_read_error:5;
		u32 xlec_write_error:5;
		u32 xlec_desc_error:5;
		u32 xlec_reserved2:1;
		u32 xlec_non_inc_mode:1;
		u32 xlec_pollmode_wb_enabled:1;
	};
	u32 xlec_value;
} xdma_lite_chan_ctrl_status_t;

typedef	union xdma_lite_dma_alignments {
	struct {
		u32 xlda_addr_bits:8;
		u32 xlda_len_granularity:8;
		u32 xlda_addr_alignment:8;
	};
	u32 xlda_alignments;
} xdma_lite_dma_alignments_t;

typedef struct xdma_lite_chan_reg {
	xdma_lite_identifier_t xlchr_id;
	xdma_lite_chan_ctrl_status_t xlchr_ctrl;
	xdma_lite_chan_ctrl_status_t xlchr_ctrl_w1s;
	xdma_lite_chan_ctrl_status_t xlchr_ctrl_w1c;
	u32 xlchr_reserved1[12];	/* padding */

	xdma_lite_chan_ctrl_status_t xlchr_status;
	xdma_lite_chan_ctrl_status_t xlchr_status_rc;
	u32 xlchr_completed_desc_count;
	xdma_lite_dma_alignments_t xlchr_alignments;
	u32 xlchr_reserved2[14];	/* padding */

	u32 xlchr_poll_mode_wb_lo;
	u32 xlchr_poll_mode_wb_hi;

	xdma_lite_chan_ctrl_status_t xlchr_intr_mask;
	xdma_lite_chan_ctrl_status_t xlchr_intr_mask_w1s;
	xdma_lite_chan_ctrl_status_t xlchr_intr_mask_w1c;
} xdma_lite_chan_reg_t;

typedef struct xdma_lite_sg_reg {
	xdma_lite_identifier_t xlsgr_id;
	/* padding */
	u32 xlsgr_reserved_1[31];
	/* bus address to first descriptor in host memory */
	u32 xlsgr_1st_desc_lo;
	u32 xlsgr_1st_desc_hi;
	/* number of adjacent descriptors after first_desc */
	u32 xlsgr_1st_desc_adj;
	u32 xlsgr_credits;
} xdma_lite_sg_reg_t;

typedef struct xdma_lite_engine {
	struct xdma_lite *xle_xl;
	int xle_id;
	enum dma_data_direction xle_dir;
	int xle_irq;
	u32 xle_msix_vec;

	/* Two IO request lists: running list and pending list. */
	struct list_head xle_running_list;
	struct list_head xle_pending_list;
	spinlock_t xle_lock;
	bool xle_busy;

	xdma_lite_chan_reg_t __iomem *xle_chan_regs;
	xdma_lite_sg_reg_t __iomem *xle_sg_regs;
} xdma_lite_engine_t;

typedef union xdma_lite_irq {
	u8 xirq_irq:5;
	u8 xirq_pad:3;
} xdma_lite_irq_t;

typedef union xdma_lite_irq_grp {
	struct {
		xdma_lite_irq_t xlig_irqs[4];
	};
	u32 xlig_value;
} xdma_lite_irq_grp_t;

typedef struct xdma_lite_intr_reg {
	xdma_lite_identifier_t xlir_id;
	u32 xlir_usr_enable;
	u32 xlir_usr_enable_w1s;
	u32 xlir_usr_enable_w1c;
	u32 xlir_eng_enable;
	u32 xlir_eng_enable_w1s;
	u32 xlir_eng_enable_w1c;
	u32 xlir_reserved_1[9]; /* padding */

	u32 xlir_usr_request;
	u32 xlir_eng_request;
	u32 xlir_usr_pending;
	u32 xlir_eng_pending;
	u32 xlir_reserved_2[12]; /* padding */

	xdma_lite_irq_grp_t xlir_usr_irq_grp[8];
	xdma_lite_irq_grp_t xlir_eng_irq_grp[8];
} xdma_lite_intr_reg_t;

typedef struct xdma_lite_intr {
	struct xdma_lite *xint_xl;
	int xint_irq;
	u32 xint_msix_vec;

	struct eventfd_ctx *xint_eventfd_ctx;
	irq_handler_t xint_handler;
	void *xint_arg;
} xdma_lite_intr_t;

typedef struct xdma_lite_conf_reg {
	xdma_lite_identifier_t xlcr_id;
} xdma_lite_conf_reg_t;

typedef struct xdma_lite {
	struct platform_device *xl_pdev;

	xdma_lite_engine_t xl_h2c_engines[XDMAL_MAX_DMA_ENG];
	xdma_lite_engine_t xl_c2h_engines[XDMAL_MAX_DMA_ENG];
	int xl_valid_h2c_engines;
	int xl_valid_c2h_engines;
	atomic_t xl_num_h2c_ioreqs;
	atomic_t xl_num_c2h_ioreqs;

	xdma_lite_intr_t xl_intrs[XDMAL_MAX_INTR];
	int xl_usr_irq_base;
	struct mutex xl_intr_lock;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	struct msix_entry xl_msix_entry[XDMAL_MAX_INTR];
#endif

	/* HW register mappings. */
	char __iomem *xl_regs;
	xdma_lite_conf_reg_t __iomem *xl_conf_regs;
	xdma_lite_intr_reg_t __iomem *xl_intr_regs;
} xdma_lite_t;

static const char *xdmal_grp2name(enum xdma_lite_reg_grps grp)
{
	switch (grp) {
	case XLRG_H2C_CHAN:
		return "h2c channel";
	case XLRG_C2H_CHAN:
		return "c2h channel";
	case XLRG_INTR:
		return "interrupt";
	case XLRG_CONFIG:
		return "configuration";
	case XLRG_H2C_SG:
		return "h2c SGDMA";
	case XLRG_C2H_SG:
		return "c2h SGDMA";
	default:
		break;
	}

	return "unknown";
}

static inline const char *dir2name(enum dma_data_direction dir)
{
	if (dir == DMA_TO_DEVICE)
		return "H2C";
	if (dir == DMA_FROM_DEVICE)
		return "C2H";
	return "DISABLED";
}

static inline u32 xdmal_reg_rd(xdma_lite_t *xl, u32 *reg)
{
	xdma_lite_reg_addr_fmt_t addr;
	u32 val = ioread32(reg);

	addr.xlraf_val = (u64)(uintptr_t)reg;
	XDMAL_DBG(xl, "0x%x <<== %p(0x%x,0x%x,0x%x)",
		val, reg, addr.xlraf_tgt, addr.xlraf_chan, addr.xlraf_offset);
	return val;
}

static inline void xdmal_reg_wr(xdma_lite_t *xl, u32 *reg, u32 val)
{
	xdma_lite_reg_addr_fmt_t addr;

	addr.xlraf_val = (u64)(uintptr_t)reg;
	XDMAL_DBG(xl, "0x%x ==>> %p(0x%x,0x%x,0x%x)",
		val, reg, addr.xlraf_tgt, addr.xlraf_chan, addr.xlraf_offset);
	iowrite32(val, reg);
}

static bool xdmal_check_identifier(xdma_lite_t *xl, xdma_lite_identifier_t *id,
	u32 chan_id, u32 grp)
{
	if (id->xli_xdma_magic != XDMAL_IDENTIFIER ||
		id->xli_xdma_grp != grp || id->xli_id != chan_id ||
		id->xli_is_stream) {
		XDMAL_ERR(xl, "detected invalid %s[%d] reg grp",
			xdmal_grp2name(grp), id->xli_id);
		XDMAL_ERR(xl, "magic(0x%x), grp(0x%x), chan(0x%x)",
			id->xli_xdma_magic, id->xli_xdma_grp, id->xli_id);
		return false;
	}
	return true;
}

/* DMA irqs come first. User irqs follow. */
static inline bool xdmal_is_dma_intr(xdma_lite_intr_t *intr)
{
	return intr->xint_irq < intr->xint_xl->xl_usr_irq_base;
}

/* Return irq relative to DMA intrs or user intrs. */
static inline int xdmal_get_rel_irq(xdma_lite_intr_t *intr)
{
	return xdmal_is_dma_intr(intr) ?
		intr->xint_irq :
		intr->xint_irq - intr->xint_xl->xl_usr_irq_base;
}

static inline bool xdmal_intr_in_use(xdma_lite_intr_t *intr)
{
	return intr->xint_msix_vec != 0;
}

static size_t xdmal_dump(xdma_lite_t *xl,
	size_t(*dump_fn)(void *, char *, size_t), void *arg, const char *title)
{
	char *buf;
	size_t size = 1024; /* max print from kernel per msg */
	size_t n;

	/* can be used in atomic context */
	buf = kvmalloc(size, GFP_NOWAIT | GFP_KERNEL);
	if (buf == NULL) {
		XDMAL_ERR(xl, "Failed to alloc %ld bytes of dump buffer", size);
		return 0;
	}
	n = dump_fn(arg, buf, size);
	if (n == 0) {
		kvfree(buf);
		return 0;
	}

	buf[size - 1] = '\0';
	XDMAL_INFO(xl,
		"\n==== BEGIN DUMPING %s ====\n%s====   END DUMPING %s ====",
		title, buf, title);
	kvfree(buf);
	return n;
}

static size_t xdmal_dump_io_request_header(void *arg, char *buf, size_t size)
{
	xdma_lite_io_req_t *ioreq = (xdma_lite_io_req_t *)arg;
	size_t n = 0;

	n += XDMAL_SNPRT(buf, size, n, "IO request @0x%p:\n", ioreq);
	n += XDMAL_SNPRT(buf, size, n, "\thost VA: 0x%p\n",
		ioreq->xlir_usr_addr);
	n += XDMAL_SNPRT(buf, size, n, "\tdev EP: 0x%llx\n",
		ioreq->xlir_ep_addr);
	n += XDMAL_SNPRT(buf, size, n, "\tIO size: 0x%lx\n", ioreq->xlir_size);
	n += XDMAL_SNPRT(buf, size, n, "\tIO direction: %s\n",
		ioreq->xlir_write ? "host to card" : "card to host");

	return n;
}

static size_t xdmal_dump_sg_table_header(void *arg, char *buf, size_t size)
{
	xdma_lite_io_req_t *ioreq = (xdma_lite_io_req_t *)arg;
	struct scatterlist *sg;
	size_t totallen = 0;
	int totalents = 0;
	int curr_ent = 0;
	size_t n = 0;

	for (totalents = 0, sg = ioreq->xlir_sgt.sgl; sg;
		totalents++, sg = sg_next(sg)) {
		totallen += sg_dma_len(sg);
		if (sg == ioreq->xlir_curr_sg)
			curr_ent = totalents;
	}

	n += XDMAL_SNPRT(buf, size, n, "S/G table for IO request @0x%p:\n",
		ioreq);
	n += XDMAL_SNPRT(buf, size, n, "\tEntries: %d\n", totalents);
	n += XDMAL_SNPRT(buf, size, n, "\tData size: 0x%lx bytes\n", totallen);
	n += XDMAL_SNPRT(buf, size, n,
		"\tNext desc list starts: sg[%d][0x%lx] ==> 0x%llx\n",
		curr_ent, ioreq->xlir_curr_sg_offset,
		ioreq->xlir_ep_addr + (u64)ioreq->xlir_curr_bytes);

	/* Reset sg dump helper for dumping entries. */
	ioreq->xlir_sg_dump_ent = 0;
	return n;
}

static size_t xdmal_dump_sg_table_entries(void *arg, char *buf, size_t size)
{
/* Dump at most 8 entries per call to avoid overflow buf passed in. */
#define	MAX_SG_DUMP_ENTRIES	8
	xdma_lite_io_req_t *ioreq = (xdma_lite_io_req_t *)arg;
	int thisent = ioreq->xlir_sg_dump_ent;
	u64 epaddr = ioreq->xlir_ep_addr;
	struct scatterlist *sg = NULL;
	size_t n = 0;
	size_t i;

	/* Figure out where we were left. */
	for (i = 0, sg = ioreq->xlir_sgt.sgl;
		i < thisent; i++, sg = sg_next(sg))
		epaddr += sg_dma_len(sg);

	for (; sg && i < thisent + MAX_SG_DUMP_ENTRIES;
		i++, sg = sg_next(sg)) {
		unsigned int sz = sg_dma_len(sg);

		n += XDMAL_SNPRT(buf, size, n,
			"[%ld]: pa=0x%llx dma=0x%llx ep=0x%llx size=0x%x\n",
			i, sg_phys(sg), sg_dma_address(sg), epaddr, sz);
		epaddr += sz;
	}

	/* Remember where we are. */
	ioreq->xlir_sg_dump_ent = i;
	return n;
}

static void xdmal_dump_sg_table(xdma_lite_io_req_t *ioreq)
{
	xdma_lite_t *xl = ioreq->xlir_xl;
	size_t n;

	(void)xdmal_dump(xl, xdmal_dump_sg_table_header, ioreq,
		"S/G table header");
	n = xdmal_dump(xl, xdmal_dump_sg_table_entries, ioreq,
		"S/G table entries");
	while (n) {
		n = xdmal_dump(xl, xdmal_dump_sg_table_entries, ioreq,
			"S/G table entries (continue)");
	}
}

static size_t xdmal_dump_descs_header(void *arg, char *buf, size_t size)
{
	xdma_lite_io_req_t *ioreq = (xdma_lite_io_req_t *)arg;
	size_t totallen = 0;
	size_t n = 0;
	int i;

	for (i = 0; i < ioreq->xlir_ndescs; i++)
		totallen += ioreq->xlir_descs[i].xld_bytes;

	n += XDMAL_SNPRT(buf, size, n, "Desc list for IO request @0x%p:\n",
		ioreq);
	n += XDMAL_SNPRT(buf, size, n, "\tBus addr: @0x%llx\n",
		ioreq->xlir_descs_bus_addr);
	n += XDMAL_SNPRT(buf, size, n, "\tEntries: %lu\n", ioreq->xlir_ndescs);
	n += XDMAL_SNPRT(buf, size, n, "\tData size: 0x%lx bytes\n", totallen);

	/* Reset desc list dump helper fields for dumping entries. */
	ioreq->xlir_desc_dump_ent = 0;

	return n;
}

static size_t xdmal_dump_descs_entries(void *arg, char *buf, size_t size)
{
/* Dump at most 8 entries per call to avoid overflow buf. */
#define	MAX_SG_DUMP_ENTRIES	8
	xdma_lite_io_req_t *ioreq = (xdma_lite_io_req_t *)arg;
	size_t n = 0;
	size_t i;
	size_t entries = min(ioreq->xlir_ndescs,
		ioreq->xlir_desc_dump_ent + MAX_SG_DUMP_ENTRIES);

	for (i = ioreq->xlir_desc_dump_ent; i < entries; i++) {
		xdma_lite_desc_t *r = &ioreq->xlir_descs[i];
		n += XDMAL_SNPRT(buf, size, n, "[%ld]: ctrl=0x%x ",
			i, r->xld_control);
		n += XDMAL_SNPRT(buf, size, n,
			"0x%llx==>0x%llx next=0x%llx size=0x%x\n",
			*(u64 *)&r->xld_src_addr_lo,
			*(u64 *)&r->xld_dst_addr_lo,
			*(u64 *)&r->xld_next_lo,
			r->xld_bytes);
	}

	/* Remember where we are. */
	ioreq->xlir_desc_dump_ent = i;
	return n;
}

static void xdmal_dump_descs(xdma_lite_io_req_t *ioreq)
{
	xdma_lite_t *xl = ioreq->xlir_xl;
	size_t n;

	(void)xdmal_dump(xl, xdmal_dump_descs_header, ioreq,
		"Descriptor list header");
	n = xdmal_dump(xl, xdmal_dump_descs_entries, ioreq,
		"Descriptor list entries");
	while (n) {
		n = xdmal_dump(xl, xdmal_dump_descs_entries, ioreq,
			"Descriptor list entries (continue)");
	}
}

static void xdmal_dump_io_request(xdma_lite_io_req_t *ioreq)
{
	xdma_lite_t *xl = ioreq->xlir_xl;

	(void)xdmal_dump(xl, xdmal_dump_io_request_header, ioreq,
		"IO Request header");
	if (ioreq->xlir_sgt.sgl)
		xdmal_dump_sg_table(ioreq);
	if (ioreq->xlir_descs)
		xdmal_dump_descs(ioreq);
}

static size_t xdmal_dump_engine_chan_regs(void *arg, char *buf, size_t size)
{
	xdma_lite_engine_t *eng = (xdma_lite_engine_t *)arg;
	struct xdma_lite *xl = eng->xle_xl;
	size_t n = 0;
	xdma_lite_dma_alignments_t alignments;

	n += XDMAL_SNPRT(buf, size, n, "\tidentifier: 0x%x\n",
		xdmal_reg_rd(xl,
		&eng->xle_chan_regs->xlchr_id.xli_value));
	n += XDMAL_SNPRT(buf, size, n, "\tstatus: 0x%x\n",
		xdmal_reg_rd(xl,
		&eng->xle_chan_regs->xlchr_status.xlec_value));
	n += XDMAL_SNPRT(buf, size, n, "\tcomp desc cnt: %u\n",
		xdmal_reg_rd(xl,
		&eng->xle_chan_regs->xlchr_completed_desc_count));
	alignments.xlda_alignments = xdmal_reg_rd(xl,
		&eng->xle_chan_regs->xlchr_alignments.xlda_alignments);
	n += XDMAL_SNPRT(buf, size, n, "\taddress bits: %u\n",
		alignments.xlda_addr_bits);
	n += XDMAL_SNPRT(buf, size, n, "\tlen granularity alignment: %u\n",
		alignments.xlda_len_granularity);
	n += XDMAL_SNPRT(buf, size, n, "\taddress alignment: %u\n",
		alignments.xlda_addr_alignment);
	n += XDMAL_SNPRT(buf, size, n, "\tpoll mode wb low: 0x%x\n",
		xdmal_reg_rd(xl,
		&eng->xle_chan_regs->xlchr_poll_mode_wb_lo));
	n += XDMAL_SNPRT(buf, size, n, "\tpoll mode wb high: 0x%x\n",
		xdmal_reg_rd(xl,
		&eng->xle_chan_regs->xlchr_poll_mode_wb_hi));
	n += XDMAL_SNPRT(buf, size, n, "\tinterrupt masks: 0x%x\n",
		xdmal_reg_rd(xl,
		&eng->xle_chan_regs->xlchr_intr_mask.xlec_value));

	return n;
}

static size_t xdmal_dump_engine_sg_regs(void *arg, char *buf, size_t size)
{
	xdma_lite_engine_t *eng = (xdma_lite_engine_t *)arg;
	struct xdma_lite *xl = eng->xle_xl;
	size_t n = 0;

	n += XDMAL_SNPRT(buf, size, n, "\tidentifier: 0x%x\n",
		xdmal_reg_rd(xl,
		&eng->xle_sg_regs->xlsgr_id.xli_value));
	n += XDMAL_SNPRT(buf, size, n, "\tdesc list low: 0x%x\n",
		xdmal_reg_rd(xl,
		&eng->xle_sg_regs->xlsgr_1st_desc_lo));
	n += XDMAL_SNPRT(buf, size, n, "\tdesc list high: 0x%x\n",
		xdmal_reg_rd(xl,
		&eng->xle_sg_regs->xlsgr_1st_desc_hi));
	n += XDMAL_SNPRT(buf, size, n, "\tadj descs: 0x%x\n",
		xdmal_reg_rd(xl,
		&eng->xle_sg_regs->xlsgr_1st_desc_adj));
	n += XDMAL_SNPRT(buf, size, n, "\tdesc credits: 0x%x\n",
		xdmal_reg_rd(xl,
		&eng->xle_sg_regs->xlsgr_credits));

	return n;
}

static size_t xdmal_dump_engine_regs(void *arg, char *buf, size_t size)
{
	xdma_lite_engine_t *eng = (xdma_lite_engine_t *)arg;
	size_t n = 0;

	n += XDMAL_SNPRT(buf, size, n, "%s channel[%d]:\n",
		dir2name(eng->xle_dir), eng->xle_id);
	n += xdmal_dump_engine_chan_regs(eng, buf + n, SPC_LEFT(size, n));
	n += XDMAL_SNPRT(buf, size, n, "%s SGDMA[%d]:\n",
		dir2name(eng->xle_dir), eng->xle_id);
	n += xdmal_dump_engine_sg_regs(eng, buf + n, SPC_LEFT(size, n));
	return n;
}

static size_t xdmal_dump_intr_regs(void *arg, char *buf, size_t size)
{
	xdma_lite_t *xl = (xdma_lite_t *)arg;
	int i;
	size_t n = 0;

	n += XDMAL_SNPRT(buf, size, n, "user intr enable: 0x%x\n",
		xdmal_reg_rd(xl, &xl->xl_intr_regs->xlir_usr_enable));

	n += XDMAL_SNPRT(buf, size, n, "user intr request: 0x%x\n",
		xdmal_reg_rd(xl, &xl->xl_intr_regs->xlir_usr_request));
	n += XDMAL_SNPRT(buf, size, n, "user intr pending: 0x%x\n",
		xdmal_reg_rd(xl, &xl->xl_intr_regs->xlir_usr_pending));
	for (i = 0; i < 2; i++) {
		n += XDMAL_SNPRT(buf, size, n, "user intr vector[%d]: 0x%x\n",
			i, xdmal_reg_rd(xl,
			&xl->xl_intr_regs->xlir_usr_irq_grp[i].xlig_value));
	}

	n += XDMAL_SNPRT(buf, size, n, "engine intr enable: 0x%x\n",
		xdmal_reg_rd(xl, &xl->xl_intr_regs->xlir_eng_enable));
	n += XDMAL_SNPRT(buf, size, n, "engine intr request: 0x%x\n",
		xdmal_reg_rd(xl, &xl->xl_intr_regs->xlir_eng_request));
	n += XDMAL_SNPRT(buf, size, n, "engine intr pending: 0x%x\n",
		xdmal_reg_rd(xl, &xl->xl_intr_regs->xlir_eng_pending));
	for (i = 0; i < 2; i++) {
		n += XDMAL_SNPRT(buf, size, n, "engine intr vector[%d]: 0x%x\n",
			i, xdmal_reg_rd(xl,
			&xl->xl_intr_regs->xlir_eng_irq_grp[i].xlig_value));
	}
	return n;
}

static irqreturn_t xdmal_isr(int vec, void *arg)
{
	xdma_lite_intr_t *intr = (xdma_lite_intr_t *)arg;
	xdma_lite_t *xl = intr->xint_xl;
	int ret = IRQ_HANDLED;
	bool isdma = xdmal_is_dma_intr(intr);
	int rel_irq = xdmal_get_rel_irq(intr);

	XDMAL_INFO(xl, "%s IRQ(%d) FIRED", isdma ? "DMA" : "USER", rel_irq);

	if (intr->xint_handler)
		ret = intr->xint_handler(rel_irq, intr->xint_arg);

	if (intr->xint_eventfd_ctx != NULL)
		eventfd_signal(intr->xint_eventfd_ctx, 1);

	return ret;
}

static int xdmal_alloc_all_irqs(xdma_lite_t *xl)
{
	int nvec = XDMAL_MAX_INTR;
	int rv;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	rv = pci_alloc_irq_vectors(XDMAL_PCIDEV(xl), nvec, nvec, PCI_IRQ_MSIX);
#else
	int i;
	for (i = 0; i < nvec; i++)
		xl->xl_msix_entry[i].entry = i;
	rv = pci_enable_msix(XDMAL_PCIDEV(xl), xl->xl_msix_entry, nvec);
#endif
	return rv;
}

static void xdmal_release_all_irqs(xdma_lite_t *xl)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
	pci_free_irq_vectors(XDMAL_PCIDEV(xl));
#else
	pci_disable_msix(XDMAL_PCIDEV(xl));
#endif
}

static int xdmal_add_isr(xdma_lite_intr_t *intr)
{
	int rv;
	u32 vector;
	xdma_lite_t *xl = intr->xint_xl;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	vector = pci_irq_vector(XDMAL_PCIDEV(xl), intr->xint_irq);
#else
	vector = xl->xl_msix_entry[intr->xint_irq].vector;
#endif
	rv = request_irq(vector, xdmal_isr, 0, "xdma-lite", intr);
	if (rv)
		XDMAL_ERR(xl, "request irq#%d failed: %d", intr->xint_irq, rv);
	else
		intr->xint_msix_vec = vector;
	return rv;
}

static void xdmal_rem_isr(xdma_lite_intr_t *intr)
{
	if (intr->xint_msix_vec) {
		free_irq(intr->xint_msix_vec, intr);
		intr->xint_msix_vec = 0;
	}
}

static int xdmal_intr_config(xdma_lite_intr_t *intr, bool enable)
{
	u32 *intr_reg;
	int ret = 0;
	xdma_lite_t *xl = intr->xint_xl;

	mutex_lock(&xl->xl_intr_lock);

	if (!xdmal_intr_in_use(intr)) {
		XDMAL_ERR(xl, "configuring unregistered irq: %d",
			intr->xint_irq);
		ret = -EINVAL;
		goto done;
	}
	
	if (xdmal_is_dma_intr(intr)) {
		intr_reg = enable ? &xl->xl_intr_regs->xlir_eng_enable_w1s :
			&xl->xl_intr_regs->xlir_eng_enable_w1c;
	} else {
		intr_reg = enable ? &xl->xl_intr_regs->xlir_usr_enable_w1s :
			&xl->xl_intr_regs->xlir_usr_enable_w1c;
	}

	xdmal_reg_wr(xl, intr_reg, 1 << xdmal_get_rel_irq(intr));
done:
	mutex_unlock(&xl->xl_intr_lock);
	return ret;
}

static int xdmal_intr_register(xdma_lite_intr_t *intr,
	irq_handler_t handler, void *arg, int event_fd)
{
	xdma_lite_t *xl = intr->xint_xl;
	struct eventfd_ctx *trigger = NULL;
	int ret = 0;

	/* Need at least fd or handler. */
	if (event_fd < 0 && handler == NULL) {
		XDMAL_ERR(xl, "registering NULL handler and bad eventfd for %d",
			intr->xint_irq);
		return -EINVAL;
	}

	/* Valid eventfd? */
	if (event_fd >= 0) {
		trigger = eventfd_ctx_fdget(event_fd);
		if (IS_ERR(trigger)) {
			XDMAL_ERR(xl, "get eventfd ctx failed");
			return -EFAULT;
		}
	}

	mutex_lock(&xl->xl_intr_lock);

	if (xdmal_intr_in_use(intr)) {
		XDMAL_ERR(xl, "IRQ (%d) is busy", intr->xint_irq);
		ret = -EBUSY;
	} else {
		intr->xint_eventfd_ctx = trigger;
		intr->xint_handler = handler;
		intr->xint_arg = arg;
		ret = xdmal_add_isr(intr);
		if (ret) {
			eventfd_ctx_put(trigger);
			intr->xint_eventfd_ctx = NULL;
			intr->xint_handler = NULL;
			intr->xint_arg = NULL;
		}
	}

	mutex_unlock(&xl->xl_intr_lock);
	return ret;
}

static void xdmal_intr_unregister(xdma_lite_intr_t *intr)
{
	xdma_lite_t *xl = intr->xint_xl;

	mutex_lock(&xl->xl_intr_lock);

	/* Disable intr on HW. */
	if (xdmal_is_dma_intr(intr)) {
		xdmal_reg_wr(xl, &xl->xl_intr_regs->xlir_eng_enable_w1c,
			1 << xdmal_get_rel_irq(intr));
	} else {
		xdmal_reg_wr(xl, &xl->xl_intr_regs->xlir_usr_enable_w1c,
			1 << xdmal_get_rel_irq(intr));
	}

	/* Make sure on-going intr is done. */
	xdmal_rem_isr(intr);

	if (intr->xint_eventfd_ctx != NULL)
		eventfd_ctx_put(intr->xint_eventfd_ctx);
	intr->xint_eventfd_ctx = NULL;
	intr->xint_handler = NULL;
	intr->xint_arg = NULL;

	mutex_unlock(&xl->xl_intr_lock);
}

static int xdmal_user_intr_config(struct platform_device *pdev,
	u32 irq, bool enable)
{
	xdma_lite_t *xl = platform_get_drvdata(pdev);

	if (irq >= XDMAL_MAX_USER_INTR) {
		XDMAL_ERR(xl, "invalid user irq: %d", irq);
		return -EINVAL;
	}

	return xdmal_intr_config(&xl->xl_intrs[irq + xl->xl_usr_irq_base],
		enable);
}

static int xdmal_user_intr_register(struct platform_device *pdev,
	u32 irq, irq_handler_t handler, void *arg, int event_fd)
{
	xdma_lite_t *xl = platform_get_drvdata(pdev);

	if (irq >= XDMAL_MAX_USER_INTR) {
		XDMAL_ERR(xl, "invalid user irq: %d", irq);
		return -EINVAL;
	}

	return xdmal_intr_register(&xl->xl_intrs[irq + xl->xl_usr_irq_base],
		handler, arg, event_fd);
}

static int xdmal_user_intr_unregister(struct platform_device *pdev, u32 irq)
{
	xdma_lite_t *xl = platform_get_drvdata(pdev);

	if (irq >= XDMAL_MAX_USER_INTR) {
		XDMAL_ERR(xl, "invalid user irq: %d", irq);
		return -EINVAL;
	}

	xdmal_intr_unregister(&xl->xl_intrs[irq + xl->xl_usr_irq_base]);
	return 0;
}

static void xdmal_init_intr(xdma_lite_t *xl, int irq, xdma_lite_intr_t *intr)
{
	int rel_irq;
	u32 *intr_w1c;
	xdma_lite_irq_grp_t *intr_vec;
	xdma_lite_irq_grp_t grp;
	const int irq_per_grp =
		sizeof(xdma_lite_irq_grp_t) / sizeof(xdma_lite_irq_t);

	intr->xint_xl = xl;
	intr->xint_irq = irq;
	intr->xint_msix_vec = 0;
	intr->xint_handler = NULL;
	intr->xint_arg = NULL;
	rel_irq = xdmal_get_rel_irq(intr);

	if (xdmal_is_dma_intr(intr)) {
		intr_w1c = &xl->xl_intr_regs->xlir_eng_enable_w1c;
		intr_vec = xl->xl_intr_regs->xlir_eng_irq_grp;
	} else {
		intr_w1c = &xl->xl_intr_regs->xlir_usr_enable_w1c;
		intr_vec = xl->xl_intr_regs->xlir_usr_irq_grp;
	}

	/* Disable intr on HW initially. */
	xdmal_reg_wr(xl, intr_w1c, 1 << rel_irq);
	/* Program irqs into HW. */
	grp.xlig_value = xdmal_reg_rd(xl,
		&intr_vec[rel_irq / irq_per_grp].xlig_value);
	grp.xlig_irqs[rel_irq % irq_per_grp].xirq_irq = irq;
	xdmal_reg_wr(xl, &intr_vec[rel_irq / irq_per_grp].xlig_value,
		grp.xlig_value);
}

static void xdmal_fini_intr(xdma_lite_intr_t *intr)
{
	if (intr->xint_xl == NULL)
		return;

	xdmal_intr_unregister(intr);
	intr->xint_xl = NULL;
	intr->xint_irq = ~0;
}

static void xdmal_fini_intrs(xdma_lite_t *xl)
{
	int irq;

	if (xl->xl_intr_regs == NULL)
		return;

	for (irq = 0; irq < XDMAL_MAX_INTR; irq++)
		xdmal_fini_intr(&xl->xl_intrs[irq]);

	/* Free MSI-X vectors. */
	xdmal_release_all_irqs(xl);

	mutex_destroy(&xl->xl_intr_lock);
	xl->xl_intr_regs = NULL;
}

static int xdmal_init_intrs(xdma_lite_t *xl)
{
	int rv;
	int irq;
	xdma_lite_identifier_t id;
	xdma_lite_irq_grp_t grp;

	/* Verify the register map is valid. */
	xl->xl_intr_regs = (xdma_lite_intr_reg_t *)(xl->xl_regs +
		XDMAL_REG_GRP_OFFSET(XLRG_INTR, 0));
	id.xli_value = xdmal_reg_rd(xl, &xl->xl_intr_regs->xlir_id.xli_value);
	if (!xdmal_check_identifier(xl, &id, 0, XLRG_INTR)) {
		xl->xl_intr_regs = NULL;
		return -EINVAL;
	}

	mutex_init(&xl->xl_intr_lock);

	/* Ask system for enough MSI-X intr vectors. */
	rv = xdmal_alloc_all_irqs(xl);
	if (rv < 0)
		goto fail;

	/*
	 * Figure out the base of user irq.
	 * The irq may have been hard-coded in HW.
	 * If not, use XDMAL_MAX_DMA_INTR to make sure it's after DMA intrs.
	 */
	grp.xlig_value = xdmal_reg_rd(xl,
		&xl->xl_intr_regs->xlir_usr_irq_grp[0].xlig_value);
	if (grp.xlig_irqs[0].xirq_irq > 0)
		xl->xl_usr_irq_base = grp.xlig_irqs[0].xirq_irq;
	else
		xl->xl_usr_irq_base = XDMAL_MAX_DMA_INTR;

	for (irq = 0; irq < XDMAL_MAX_INTR; irq++)
		xdmal_init_intr(xl, irq, &xl->xl_intrs[irq]);

	return 0;

fail:
	xdmal_fini_intrs(xl);
	return rv;
}

static void xdmal_unmap_bar(xdma_lite_t *xl)
{
	if (xl->xl_regs == NULL)
		return;
	iounmap(xl->xl_regs);
	xl->xl_regs = NULL;
	xl->xl_conf_regs = NULL;
}

static int xdmal_map_bar(xdma_lite_t *xl)
{
	struct resource *res;
	xdma_lite_identifier_t id;

	res = platform_get_resource(xl->xl_pdev, IORESOURCE_MEM, 0);
	if (res == NULL) {
		XDMAL_ERR(xl, "failed to get IO resource");
		return -EINVAL;
	}
	xl->xl_regs = ioremap_nocache(res->start, res->end - res->start + 1);
	if (xl->xl_regs == NULL) {
		XDMAL_ERR(xl, "failed to map IO resource");
		return -EINVAL;
	}

	/* Verify the register map is valid. */
	xl->xl_conf_regs = (xdma_lite_conf_reg_t *)(xl->xl_regs +
		XDMAL_REG_GRP_OFFSET(XLRG_CONFIG, 0));
	id.xli_value = xdmal_reg_rd(xl, &xl->xl_conf_regs->xlcr_id.xli_value);
	if (!xdmal_check_identifier(xl, &id, 0, XLRG_CONFIG))
		return -EINVAL;

	XDMAL_INFO(xl, "successfully mapped XDMA IP, ver: 0x%x", id.xli_ver);
	return 0;
}

static inline dma_addr_t
xdmal_desc_dma_addr(xdma_lite_io_req_t *ioreq, int idx)
{
	return ioreq->xlir_descs_bus_addr + idx * sizeof(xdma_lite_desc_t);
}

static void xdmal_fill_one_desc(xdma_lite_io_req_t *ioreq, int idx,
	dma_addr_t busaddr, u64 epaddr, u64 len)
{
#define	XDMA_LITE_DESC_MAGIC		0xad4b
#define	XDMA_LITE_DESC_BLK_BOND_MASK	(4096 - 1)

	xdma_lite_desc_t *desc = &ioreq->xlir_descs[idx];
	int last_desc_idx = XDMA_LITE_NUM_DESC(ioreq->xlir_descs_total_len) - 1;
	/* Desc block can't across 4k boundary */
	int desc_blk_within_boundary = 1 + XDMA_LITE_NUM_DESC(
		~xdmal_desc_dma_addr(ioreq,idx) & XDMA_LITE_DESC_BLK_BOND_MASK);
	int adj = last_desc_idx - idx - 1;

	BUG_ON(idx > last_desc_idx);
	BUG_ON(len > XDMA_LITE_DESC_BLEN_MAX);
	desc->xld_magic = XDMA_LITE_DESC_MAGIC;
	desc->xld_bytes = len;

	if (ioreq->xlir_write) {
		desc->xld_src_addr_lo = (u32)(busaddr);
		desc->xld_src_addr_hi = (u32)(busaddr >> 32);
		desc->xld_dst_addr_lo = (u32)(epaddr);
		desc->xld_dst_addr_hi = (u32)(epaddr >> 32);
	} else {
		desc->xld_src_addr_lo = (u32)(epaddr);
		desc->xld_src_addr_hi = (u32)(epaddr >> 32);
		desc->xld_dst_addr_lo = (u32)(busaddr);
		desc->xld_dst_addr_hi = (u32)(busaddr >> 32);
	}

	if (idx == last_desc_idx) {
		desc->xld_next_lo = 0;
		desc->xld_next_hi = 0;
		desc->xld_stop = 1; /* Indicate the last desc */
		desc->xld_completed = 1; /* Request intr when done */
		desc->xld_next_adj = 0;
	} else {
		dma_addr_t next = xdmal_desc_dma_addr(ioreq, idx + 1);
		desc->xld_next_lo = (u32)(next);
		desc->xld_next_hi = (u32)(next >> 32);
		desc->xld_stop = 0;
		desc->xld_completed = 0;
	}

	adj = min(adj, XDMA_LITE_DESC_MAX_ADJ);
	adj = min(adj, desc_blk_within_boundary - 2);
	desc->xld_next_adj = adj > 0 ? adj : 0;
}

static void xdmal_init_descs(xdma_lite_io_req_t *ioreq)
{
	struct scatterlist *sg = ioreq->xlir_curr_sg;
	int max_desc = XDMA_LITE_NUM_DESC(ioreq->xlir_descs_total_len);
	int i;

	for (i = 0; i < max_desc && sg; i++) {
		dma_addr_t curaddr =
			sg_dma_address(sg) + ioreq->xlir_curr_sg_offset;
		u64 currepaddr = ioreq->xlir_ep_addr + ioreq->xlir_curr_bytes;
		size_t curlen = min(sg_dma_len(sg) - ioreq->xlir_curr_sg_offset,
			XDMA_LITE_DESC_BLEN_MAX);

		xdmal_fill_one_desc(ioreq, i, curaddr, currepaddr, curlen);

		ioreq->xlir_curr_bytes += curlen;
		ioreq->xlir_curr_sg_offset += curlen;
		if (ioreq->xlir_curr_sg_offset == sg_dma_len(sg)) {
			/* Finish current sg, switch to next one. */
			ioreq->xlir_curr_sg = sg_next(sg);
			ioreq->xlir_curr_sg_offset = 0;
		}

		sg = ioreq->xlir_curr_sg;
	}

	ioreq->xlir_ndescs = i;
}

static void xdmal_start_ioreq(xdma_lite_io_req_t *ioreq)
{
	u32 adj;
	xdma_lite_chan_ctrl_status_t chan_ctrl = { 0 };
	xdma_lite_t *xl = ioreq->xlir_xl;
	xdma_lite_engine_t *eng = ioreq->xlir_engine;

	/* Program the 1st desc into SGDMA. */
	xdmal_reg_wr(xl, &eng->xle_sg_regs->xlsgr_1st_desc_lo,
		(u32)ioreq->xlir_descs_bus_addr);
	xdmal_reg_wr(xl, &eng->xle_sg_regs->xlsgr_1st_desc_hi,
		(u32)(ioreq->xlir_descs_bus_addr >> 32));
	adj = ioreq->xlir_descs[0].xld_next_adj;
	if (adj == 0)
		xdmal_reg_wr(xl, &eng->xle_sg_regs->xlsgr_1st_desc_adj, adj);
	else
		xdmal_reg_wr(xl, &eng->xle_sg_regs->xlsgr_1st_desc_adj, ++adj);

	/* Kick off the transfer. */
	chan_ctrl.xlec_run = ~0;
	chan_ctrl.xlec_ie_align_mismatch = ~0;
	chan_ctrl.xlec_ie_magic_stopped = ~0;
	chan_ctrl.xlec_ie_desc_stopped = ~0;
	chan_ctrl.xlec_ie_desc_completed = ~0;
	chan_ctrl.xlec_read_error = ~0;
	chan_ctrl.xlec_desc_error = ~0;
	xdmal_reg_wr(xl, &eng->xle_chan_regs->xlchr_ctrl.xlec_value,
		chan_ctrl.xlec_value);
}

static void xdmal_fini_engine(xdma_lite_engine_t *eng)
{
	if (eng->xle_xl == NULL)
		return;

	/* Disable intrs. */
	if (eng->xle_chan_regs) {
		xdmal_reg_wr(eng->xle_xl,
			&eng->xle_chan_regs->xlchr_intr_mask.xlec_value, 0);
	}
	if (eng->xle_irq >= 0)
		xdmal_intr_unregister(&eng->xle_xl->xl_intrs[eng->xle_irq]);
	eng->xle_irq = -1;
	eng->xle_xl = NULL;
	eng->xle_dir = DMA_NONE;
	eng->xle_chan_regs = NULL;
	eng->xle_sg_regs = NULL;
}

static irqreturn_t xdmal_engine_isr(int irq, void *arg)
{
	xdma_lite_engine_t *eng = (xdma_lite_engine_t *)arg;
	xdma_lite_t *xl = eng->xle_xl;
	int ret = IRQ_HANDLED;
	xdma_lite_io_req_t *ioreq_next = NULL;
	xdma_lite_io_req_t *ioreq_done = NULL;
	xdma_lite_chan_ctrl_status_t ctl = { 0 };
	size_t ndone;
	unsigned long lkflags;

	/* Stop engine. */
	ctl.xlec_run = 1;
	xdmal_reg_wr(xl, &eng->xle_chan_regs->xlchr_ctrl_w1c.xlec_value,
		ctl.xlec_value);

	/* Find out how many descs has been finished. */
	ndone = xdmal_reg_rd(xl,
		&eng->xle_chan_regs->xlchr_completed_desc_count);

	ioreq_done = list_first_entry_or_null(&eng->xle_running_list,
		xdma_lite_io_req_t, xlir_list);
	if (ioreq_done == NULL)
		return ret;

	/* When xle_busy is true, xle_running_list belongs to ISR.
	 * ISR should not touch it when xle_busy is false. */
	BUG_ON(!eng->xle_busy);

	/* Check outstanding IO request. */
	if (ndone == ioreq_done->xlir_ndescs)
		ioreq_done->xlir_err = 0;
	else
		ioreq_done->xlir_err = -EIO;

	if (ioreq_done->xlir_err) {
		XDMAL_ERR(xl, "IO request(0x%p) failed", ioreq_done);
		(void)xdmal_dump(xl, xdmal_dump_engine_regs, eng,
			"DMA engine registers");
	} else if (ioreq_done->xlir_curr_bytes == ioreq_done->xlir_size) {
		/* IO request is done, continue with next one. */
		list_del(&ioreq_done->xlir_list);
	} else {
		/* IO request is not completed yet, continue with next part. */
		xdmal_init_descs(ioreq_done);
		xdmal_start_ioreq(ioreq_done);
		return ret;
	}

	/* Start next IO if any. */
	ioreq_next = list_first_entry_or_null(&eng->xle_running_list,
		xdma_lite_io_req_t, xlir_list);
	if (ioreq_next == NULL) {
		/* Move all IO reqs from pending list to running list. */
		spin_lock_irqsave(&eng->xle_lock, lkflags);
		list_splice_tail_init(&eng->xle_pending_list,
			&eng->xle_running_list);
		ioreq_next = list_first_entry_or_null(&eng->xle_running_list,
			xdma_lite_io_req_t, xlir_list);
		/* When xle_busy is false, next IO will be from submitter. */
		eng->xle_busy = (ioreq_next != NULL);
		spin_unlock_irqrestore(&eng->xle_lock, lkflags);
	}

	if (ioreq_next)
		xdmal_start_ioreq(ioreq_next);

	/* Finish IO request in work queue. */
	schedule_work(&ioreq_done->xlir_work);

	return ret;
}

static int xdmal_init_engine(xdma_lite_t *xl, int chan_id,
	enum dma_data_direction dir)
{
	xdma_lite_identifier_t id;
	xdma_lite_engine_t *eng = NULL;
	enum xdma_lite_reg_grps chan_grp, sg_grp;
	int ret = 0;
	xdma_lite_chan_ctrl_status_t intr = { 0 };

	BUG_ON(dir != DMA_TO_DEVICE && dir != DMA_FROM_DEVICE);

	if (dir == DMA_TO_DEVICE) {
		eng = &xl->xl_h2c_engines[chan_id];
		chan_grp = XLRG_H2C_CHAN;
		sg_grp = XLRG_H2C_SG;
	} else {
		eng = &xl->xl_c2h_engines[chan_id];
		chan_grp = XLRG_C2H_CHAN;
		sg_grp = XLRG_C2H_SG;
	}

	eng->xle_xl = xl;
	eng->xle_id = chan_id;
	eng->xle_dir = dir;
	eng->xle_irq = -1;

	spin_lock_init(&eng->xle_lock);
	INIT_LIST_HEAD(&eng->xle_running_list);
	INIT_LIST_HEAD(&eng->xle_pending_list);

	eng->xle_chan_regs = (xdma_lite_chan_reg_t *)(xl->xl_regs +
		XDMAL_REG_GRP_OFFSET(chan_grp, chan_id));
	/* Verify DMA channel register space is valid. */
	id.xli_value = xdmal_reg_rd(xl,
		&eng->xle_chan_regs->xlchr_id.xli_value);
	if (id.xli_xdma_magic == 0) {
		/* Disabled DMA engine. */
		ret = -ENOENT;
		goto fail;
	}
	if (!xdmal_check_identifier(xl, &id, chan_id, chan_grp)) {
		ret = -EINVAL;
		goto fail;
	}

	eng->xle_sg_regs = (xdma_lite_sg_reg_t *)(xl->xl_regs +
		XDMAL_REG_GRP_OFFSET(sg_grp, chan_id));
	/* Verify SGDMA register space is valid. */
	id.xli_value = xdmal_reg_rd(xl, &eng->xle_sg_regs->xlsgr_id.xli_value);
	if (!xdmal_check_identifier(xl, &id, chan_id, sg_grp)) {
		ret = -EINVAL;
		goto fail;
	}

	/* Enable IO intrs. */
	eng->xle_irq = (dir == DMA_TO_DEVICE) ? eng->xle_id :
		eng->xle_id + xl->xl_valid_h2c_engines;
	ret = xdmal_intr_register(&xl->xl_intrs[eng->xle_irq],
		xdmal_engine_isr, eng, -1);
	if (ret) {
		eng->xle_irq = -1;
		goto fail;
	} else {
		xdmal_intr_config(&xl->xl_intrs[eng->xle_irq], true);
	}

	intr.xlec_ie_desc_stopped = ~0;
	intr.xlec_ie_desc_completed = ~0;
	intr.xlec_ie_magic_stopped = ~0;
	intr.xlec_read_error = ~0;
	intr.xlec_write_error = ~0;
	xdmal_reg_wr(xl, &eng->xle_chan_regs->xlchr_intr_mask.xlec_value,
		intr.xlec_value);

	return 0;

fail:
	xdmal_fini_engine(eng);
	return ret;
}

static void xdmal_fini_engines(xdma_lite_t *xl, enum dma_data_direction dir)
{
	int i;
	xdma_lite_engine_t *eng = (dir == DMA_TO_DEVICE) ?
		xl->xl_h2c_engines : xl->xl_c2h_engines;

	for (i = 0; i < XDMAL_MAX_DMA_ENG; i++)
		xdmal_fini_engine(&eng[i]);
}

static int xdmal_init_engines(xdma_lite_t *xl, enum dma_data_direction dir)
{
	int i;
	int ret = 0;

	for (i = 0; i < XDMAL_MAX_DMA_ENG && ret == 0; i++)
		ret = xdmal_init_engine(xl, i, dir);
	if (ret != 0 && ret != -ENOENT)
		goto fail;
	--i;

	if (dir == DMA_TO_DEVICE)
		xl->xl_valid_h2c_engines = i;
	else
		xl->xl_valid_c2h_engines = i;
	XDMAL_INFO(xl, "found %d %s DMA engines", i, dir2name(dir));

	return 0;

fail:
	xdmal_fini_engines(xl, dir);
	return ret;
}

static int xdmal_config_pci(xdma_lite_t *xl)
{
#define	MAX_MRRS	512
	int rv = 0;

	/* enable relaxed ordering */
	pcie_capability_set_word(
		XDMAL_PCIDEV(xl), PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_RELAX_EN);
	/* enable extended tag */
	pcie_capability_set_word(
		XDMAL_PCIDEV(xl), PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_EXT_TAG);
	/* force MRRS to be MAX_MRRS */
	rv = pcie_get_readrq(XDMAL_PCIDEV(xl));
	if (rv < 0) {
		XDMAL_ERR(xl, "failed to read mrrs, ret = %d", rv);
	} else {
		if (rv > MAX_MRRS) {
			rv = pcie_set_readrq(XDMAL_PCIDEV(xl), MAX_MRRS);
			if (rv)
				XDMAL_ERR(xl, "can't set mrrs to %d", MAX_MRRS);
		}
	}
	/* enable bus master capability */
	pci_set_master(XDMAL_PCIDEV(xl));

	if (rv < 0)
		return rv;

	return 0;
}

static ssize_t xdmal_dma_regs_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	xdma_lite_t *xl = platform_get_drvdata(to_platform_device(dev));
	size_t size = PAGE_SIZE;
	size_t n = 0;
	int i;

	for (i = 0; i < xl->xl_valid_h2c_engines + xl->xl_valid_c2h_engines;
		i++) {
		xdma_lite_engine_t *eng;

		if (i < xl->xl_valid_h2c_engines)
			eng = &xl->xl_h2c_engines[i];
		else
			eng = &xl->xl_c2h_engines[i - xl->xl_valid_h2c_engines];
		n += xdmal_dump_engine_regs(eng, buf + n, SPC_LEFT(size, n));
	}

	return n;

}
static DEVICE_ATTR_RO(xdmal_dma_regs);

static ssize_t xdmal_intr_regs_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	xdma_lite_t *xl = platform_get_drvdata(to_platform_device(dev));
	return xdmal_dump_intr_regs(xl, buf, PAGE_SIZE);
}
static DEVICE_ATTR_RO(xdmal_intr_regs);

static struct attribute *xdma_lite_attrs[] = {
	&dev_attr_xdmal_intr_regs.attr,
	&dev_attr_xdmal_dma_regs.attr,
	NULL,
};

static const struct attribute_group xdma_lite_attrgroup = {
	.attrs = xdma_lite_attrs,
};

static int xdmal_remove(struct platform_device *pdev)
{
	xdma_lite_t *xl = platform_get_drvdata(pdev);

	sysfs_remove_group(&pdev->dev.kobj, &xdma_lite_attrgroup);
	xdmal_fini_engines(xl, DMA_FROM_DEVICE);
	xdmal_fini_engines(xl, DMA_TO_DEVICE);
	xdmal_fini_intrs(xl);
	xdmal_unmap_bar(xl);

	platform_set_drvdata(pdev, NULL);
	xocl_drvinst_free(xl);
	return 0;
}

static int xdmal_probe(struct platform_device *pdev)
{
	int ret = 0;

	xdma_lite_t *xl = xocl_drvinst_alloc(&pdev->dev, sizeof(*xl));
	if (!xl) {
		xocl_err(&pdev->dev, "alloc xdma lite dev failed");
		return -ENOMEM;
	}
	xl->xl_pdev = pdev;
	platform_set_drvdata(pdev, xl);

	xdmal_config_pci(xl);

	ret = xdmal_map_bar(xl);
	if (ret < 0)
		goto fail;

	ret = xdmal_init_intrs(xl);
	if (ret < 0)
		goto fail;

	ret = xdmal_init_engines(xl, DMA_TO_DEVICE);
	if (ret < 0)
		goto fail;
	ret = xdmal_init_engines(xl, DMA_FROM_DEVICE);
	if (ret < 0)
		goto fail;

	ret = sysfs_create_group(&pdev->dev.kobj, &xdma_lite_attrgroup);
	if (ret != 0) {
		XDMAL_ERR(xl, "failed to init sysfs");
		goto fail;
	}

	return 0;

fail:
	xdmal_remove(pdev);
	return ret;
}

/*
 * BEGIN TEST INTERFACES
 */

typedef struct xdma_lite_io_ioctl {
	void *user_addr;
	uint64_t endpoint_addr;
	uint64_t size;
	bool write; // should be op code
} xdma_lite_io_ioctl_t;

static int xdmal_open(struct inode *inode, struct file *file)
{
	xdma_lite_t *xl = xocl_drvinst_open(inode->i_cdev);

	if (xl == NULL)
		return -ENXIO;

	file->private_data = xl;
	XDMAL_INFO(xl, "OPENED");
	return 0;
}

enum xdma_lite_ioctl_cmd {
	XDMAL_IO_INIT,
	XDMAL_IO,
	XDMAL_IO_FINI,
};

static xdma_lite_engine_t *xdmal_assign_engine(xdma_lite_io_req_t *ioreq)
{
	unsigned int n;
	xdma_lite_t *xl = ioreq->xlir_xl;

	if (ioreq->xlir_write) {
		n = atomic_inc_return(&xl->xl_num_h2c_ioreqs);
		ioreq->xlir_engine =
			&xl->xl_h2c_engines[--n % xl->xl_valid_h2c_engines];
	} else {
		n = atomic_inc_return(&xl->xl_num_c2h_ioreqs);
		ioreq->xlir_engine =
			&xl->xl_c2h_engines[--n % xl->xl_valid_c2h_engines];
	}

	return ioreq->xlir_engine;
}

static void xdmal_fini_ioreq(xdma_lite_io_req_t *ioreq)
{
	struct device *dev = &XDMAL_PCIDEV(ioreq->xlir_xl)->dev;

	(void)cancel_work_sync(&ioreq->xlir_work);
	if (ioreq->xlir_descs) {
		dma_free_coherent(dev, ioreq->xlir_descs_total_len,
			ioreq->xlir_descs, ioreq->xlir_descs_bus_addr);
	}
	if (ioreq->xlir_sgt.nents) {
		pci_unmap_sg(XDMAL_PCIDEV(ioreq->xlir_xl),
			ioreq->xlir_sgt.sgl, ioreq->xlir_sgt.orig_nents,
			ioreq->xlir_write ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
	}
	if (ioreq->xlir_sgt.sgl)
		sg_free_table(&ioreq->xlir_sgt);
	if (ioreq->xlir_pages) {
		if (ioreq->xlir_pages[0]) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
			release_pages(ioreq->xlir_pages, ioreq->xlir_npages);
#else
			release_pages(ioreq->xlir_pages, ioreq->xlir_npages, 0);
#endif
		}
		kvfree(ioreq->xlir_pages);
	}
}

static void xdmal_ioreq_work(struct work_struct *work)
{
	xdma_lite_io_req_t *ioreq =
		container_of(work, xdma_lite_io_req_t, xlir_work);
	complete(&ioreq->xlir_comp);
}

static int xdmal_init_ioreq(xdma_lite_t *xl, void __user *addr, u64 ep_addr,
	u64 size, bool write, xdma_lite_io_req_t *ioreq)
{
	int ret = 0;
	struct device *dev = &XDMAL_PCIDEV(xl)->dev;
	u32 ndesc = 0;

	memset(ioreq, 0, sizeof(*ioreq));

	init_completion(&ioreq->xlir_comp);
	ioreq->xlir_xl = xl;
	ioreq->xlir_usr_addr = addr;
	ioreq->xlir_size = size;
	ioreq->xlir_ep_addr = ep_addr;
	ioreq->xlir_write = write;
	ioreq->xlir_npages = XDMAL_NUM_PAGES(addr, size);
	INIT_LIST_HEAD(&ioreq->xlir_list);
	INIT_WORK(&ioreq->xlir_work, xdmal_ioreq_work);

	ioreq->xlir_pages = kvmalloc_array(ioreq->xlir_npages,
		sizeof(struct page), GFP_KERNEL | __GFP_ZERO);
	if (ioreq->xlir_pages == NULL) {
		XDMAL_ERR(xl, "failed to alloc page array for %ld pages",
			ioreq->xlir_npages);
		ret = -ENOMEM;
		goto fail;
	}

	/* Pin down pages. */
	ret = get_user_pages_fast((u64)ioreq->xlir_usr_addr, ioreq->xlir_npages,
		(ioreq->xlir_write) ? 0 : 1, ioreq->xlir_pages);
	if (ret != ioreq->xlir_npages) {
		ret = (ret < 0) ? ret : -EINVAL;
		XDMAL_ERR(xl, "failed to pin down pages for 0x%lx bytes @0x%p",
			ioreq->xlir_size, ioreq->xlir_usr_addr);
		goto fail;
	}

	/* Get sg table from page array. */
	ret = sg_alloc_table_from_pages(&ioreq->xlir_sgt, ioreq->xlir_pages,
		ioreq->xlir_npages, XDMAL_PAGE_OFFSET(ioreq->xlir_usr_addr),
		ioreq->xlir_size, GFP_KERNEL);
	if (ret) {
		XDMAL_ERR(xl, "failed to get sgt for 0x%lx bytes @0x%p: %d",
			ioreq->xlir_size, ioreq->xlir_usr_addr, ret);
		goto fail;
	}

	/* Map it to get bus address. */
	ret = dma_map_sg(dev, ioreq->xlir_sgt.sgl, ioreq->xlir_sgt.orig_nents,
		ioreq->xlir_write ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
	if (ret == 0) {
		XDMAL_ERR(xl, "failed to map sgt for 0x%lx bytes @0x%p",
			ioreq->xlir_size, ioreq->xlir_usr_addr);
		goto fail;
	} else {
		ioreq->xlir_sgt.nents = ret;
	}

	/* Get descriptor memory space */
	ndesc = min((unsigned long)ioreq->xlir_sgt.nents, XDMAL_MAX_DESCS);
	ioreq->xlir_descs_total_len = ndesc * sizeof(xdma_lite_desc_t);
	ioreq->xlir_descs = dma_alloc_coherent(dev,
		ioreq->xlir_descs_total_len, &ioreq->xlir_descs_bus_addr,
		GFP_KERNEL);
	if (ioreq->xlir_descs == NULL) {
		XDMAL_ERR(xl, "failed to alloc 0x%x descriptors", ndesc);
		goto fail;
	}
	BUG_ON(ioreq->xlir_descs_bus_addr % sizeof(xdma_lite_desc_t));

	/* Prepare for building desc list. */
	ioreq->xlir_curr_sg = ioreq->xlir_sgt.sgl;
	ioreq->xlir_curr_sg_offset = 0;
	ioreq->xlir_curr_bytes = 0;
	/* Build first set of desc list. */
	xdmal_init_descs(ioreq);
	/* Now the IO request is fully initialized and can be send to HW. */
	xdmal_dump_io_request(ioreq);

	return 0;

fail:
	xdmal_fini_ioreq(ioreq);
	return ret;
}

static void xdmal_submit_ioreq(xdma_lite_io_req_t *ioreq)
{
	unsigned long lkflags;
	/* Associate w/ a DMA engine for doing IO later. */
	xdma_lite_engine_t *eng = xdmal_assign_engine(ioreq);

	spin_lock_irqsave(&eng->xle_lock, lkflags);
	list_add_tail(&ioreq->xlir_list, &eng->xle_pending_list);
	spin_unlock_irqrestore(&eng->xle_lock, lkflags);
}

static void xdmal_kickoff_ioreq(xdma_lite_io_req_t *ioreq)
{
	unsigned long lkflags;
	xdma_lite_engine_t *eng = ioreq->xlir_engine;

	if (eng->xle_busy)
		return;

	spin_lock_irqsave(&eng->xle_lock, lkflags);
	if (eng->xle_busy) {
		spin_unlock_irqrestore(&eng->xle_lock, lkflags);
		return;
	}

	BUG_ON(!list_empty(&eng->xle_running_list));

	/* Move all IO reqs from pending list to running list. */
	list_splice_tail_init(&eng->xle_pending_list, &eng->xle_running_list);
	eng->xle_busy = !list_empty(&eng->xle_running_list);

	if (eng->xle_busy) {
		ioreq = list_first_entry(&eng->xle_running_list,
			xdma_lite_io_req_t, xlir_list);
		xdmal_start_ioreq(ioreq);
	}

	spin_unlock_irqrestore(&eng->xle_lock, lkflags);
}

static void xdmal_wait_ioreq(xdma_lite_io_req_t *ioreq)
{
	xdma_lite_t *xl = ioreq->xlir_xl;
	unsigned long ret = wait_for_completion_timeout(
		&ioreq->xlir_comp, msecs_to_jiffies(10000));

	if (ret == 0) {
		XDMAL_ERR(xl, "IO request timed out!");
		ioreq->xlir_err = -ETIMEDOUT;
	}

	if (ioreq->xlir_err != 0) {
		XDMAL_ERR(ioreq->xlir_xl, "IO request @0x%p failed: %d!",
			ioreq, ioreq->xlir_err);
		xdmal_dump_io_request(ioreq);
	}
}

static int xdmal_io_ioctl(xdma_lite_t *xl, void __user *arg)
{
	int ret;
	xdma_lite_io_ioctl_t io = { 0 };
	xdma_lite_io_req_t ioreq = { 0 };

	ret = copy_from_user(&io, arg, sizeof(io));
	if (ret)
		return -EFAULT;

	XDMAL_INFO(xl, "XDMAL IO %s: host 0x%p, ep 0x%llx, size 0x%llx",
		io.write ? "WRITE" : "READ",
		io.user_addr, io.endpoint_addr, io.size);

	ret = xdmal_init_ioreq(xl, io.user_addr, io.endpoint_addr, io.size,
		io.write, &ioreq);
	if (ret)
		return ret;

	xdmal_submit_ioreq(&ioreq);
	xdmal_kickoff_ioreq(&ioreq);
	xdmal_wait_ioreq(&ioreq);

	xdmal_fini_ioreq(&ioreq);
	return 0;
}

static long xdmal_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	xdma_lite_t *xl = file->private_data;

	switch (cmd) {
	case XDMAL_IO_INIT:
		XDMAL_INFO(xl, "XDMAL_IO_INIT");
		break;
	case XDMAL_IO:
		return xdmal_io_ioctl(xl, (void __user *)(uintptr_t)arg);
	case XDMAL_IO_FINI:
		XDMAL_INFO(xl, "XDMAL_IO_FINI");
		break;
	}
	return 0;
}

static int xdmal_close(struct inode *inode, struct file *file)
{
	xdma_lite_t *xl = file->private_data;
	XDMAL_INFO(xl, "CLOSED");
	xocl_drvinst_close(xl);
	return 0;
}

static const struct file_operations xdma_lite_fops = {
	.owner = THIS_MODULE,
	.open = xdmal_open,
	.release = xdmal_close,
	.unlocked_ioctl = xdmal_ioctl,
};

/*
 * END TEST INTERFACES
 */

static struct xocl_dma_funcs xdma_lite_ops = {
	.user_intr_register = xdmal_user_intr_register,
	.user_intr_config = xdmal_user_intr_config,
	.user_intr_unreg = xdmal_user_intr_unregister,
};

struct xocl_drv_private xdma_lite_priv = {
	.ops = &xdma_lite_ops,
	.fops = &xdma_lite_fops,
	.dev = -1,
};

static struct platform_device_id xdma_lite_id_table[] = {
	{ XOCL_DEVNAME(XOCL_XDMA_LITE), (kernel_ulong_t)&xdma_lite_priv },
	{ },
};

static struct platform_driver	xdma_lite_driver = {
	.probe		= xdmal_probe,
	.remove		= xdmal_remove,
	.driver		= {
		.name = XOCL_DEVNAME(XOCL_XDMA_LITE),
	},
	.id_table	= xdma_lite_id_table,
};

int __init xdmal_init(void)
{
	return platform_driver_register(&xdma_lite_driver);
}

void xdmal_fini(void)
{
	return platform_driver_unregister(&xdma_lite_driver);
}
