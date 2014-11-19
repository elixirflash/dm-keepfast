#if !defined(_TRACE_MMC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MMC_H

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mmc

#include <linux/tracepoint.h>

#ifdef CREATE_TRACE_POINTS
static inline void __trace_mmc_cmd_start(struct mmc_request *mrq)
{
        mrq->cmd->start_time = sched_clock();
}

#endif

TRACE_EVENT(mmc_cmd_latency,
            TP_PROTO(struct mmc_host *host, struct mmc_request *mrq),
            TP_ARGS(host, mrq),

            TP_STRUCT__entry(
                    __field(u32,	arg)
                    __field(u32,	blocks)
                    __field(u64,        start_time)
                    __field(u64,	latency)
                    __field(u64,        latency_v)
                    __field(u64,        t)                    
                    __field(u32,        usec_rem)
                    __field(u32,        secs)
                    __field(u32,        opcode)
                    __field(u32,        tagid)
                    __field(u32,        flags)                    
            ),

            TP_fast_assign(
                           __entry->arg		= (u32)mrq->cmd->arg;
                           __entry->blocks	= mrq->data ? mrq->data->blocks : 0;
                           __entry->start_time  = mrq->cmd->start_time;
                           __entry->latency     = sched_clock() - mrq->cmd->start_time + 500;
                           __entry->latency_v   = __entry->latency;
                           __entry->t           = do_div(__entry->latency, 1000) ? __entry->latency : __entry->latency;
                           __entry->usec_rem    = (u32)do_div(__entry->t, USEC_PER_SEC);
                           __entry->secs        = (u32)__entry->t;
                           __entry->opcode      = mrq->cmd->opcode;
                           __entry->tagid       = 0;//(u32)((mrq->sbc->arg >> 25) & 0xf);
                           __entry->flags       = mrq->data ? mrq->data->flags : 0;
                           ),
            
            TP_printk("op=%c(%u,%u) lat=%1u.%06u(%llu) sec=%u blks=%u\n",
                      __entry->flags ==  MMC_DATA_WRITE ? 'W' :
                      __entry->flags == MMC_DATA_READ ? 'R' : 'C',
                      (u32)__entry->opcode,
                      (u32)__entry->tagid,
                      (u32)__entry->secs,
                      (u32)__entry->usec_rem,
                      (u64)__entry->latency_v,
                      (u32)__entry->arg,
                      (u32)__entry->blocks
                      )
);

#endif /* _TRACE_MMC_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

