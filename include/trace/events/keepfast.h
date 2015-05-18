#undef TRACE_SYSTEM
#define TRACE_SYSTEM keepfast

#if !defined(_TRACE_KEEPFAST_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KEEPFAST_H

//n#undef TRACE_SYSTEM
//#define TRACE_SYSTEM keepfast

#include <linux/tracepoint.h>

/* request.c */

TRACE_EVENT(keepfast_op,
            TP_PROTO(struct cache_entry *ce, int op),
            TP_ARGS(ce, op),

            TP_STRUCT__entry(
                    __field(u32,	seg   )    
                    __field(u32,        idx      	)
                    __field(u32,	oblock      		)
                    __field(u32,        cblock		        )
                    __field(u8,	        op      		)
            ),

            TP_fast_assign(
                           __entry->seg	= ce->seg ? ce->seg->global_id : -1;
                           __entry->idx	= ce->mb ? ce->mb->idx_packed_v>>4 : -1;
                           __entry->oblock     = ce->se.oblock;
                           __entry->cblock     = ce->mb ? ce->se.cblock : ce->cblock;                    
                    __entry->op             = op;
            ),
            
            TP_printk("seg_id=%d idx=%d oblock=%d cblock=%d %s",
                      __entry->seg,
                      __entry->idx,
                      __entry->oblock,
                      __entry->cblock,
                    __entry->op == 0 ? "Read-hit" : \
                              (u32)__entry->op == 1 ? "Read-miss" : \
                              (u32)__entry->op == 2 ? "Read-inv" : \
                              (u32)__entry->op == 3 ? "Write-hit" : \
                              (u32)__entry->op == 4 ? "Write-miss" : \
                              (u32)__entry->op == 5 ? "Write-replace" : \
                              (u32)__entry->op == 6 ? "Flush" : \
                              (u32)__entry->op == 7 ? "Recovery" : "X"
                      )
);

TRACE_EVENT(keepfast_worker,
            TP_PROTO(u32 block, u32 op),
            TP_ARGS(block, op),

            TP_STRUCT__entry(
                    __field(u32,	        block	)
                    __field(u32,	        op	)                    
                             ),

            TP_fast_assign(
                    __entry->block		= block;
                    __entry->op		        = op;                    
                           ),

            TP_printk("%s(%d)",
                      __entry->op == 0 ? "Read-originblock" : "Write cacheblock",
                      (u32)__entry->block                      
                      )
);
#if 0
TRACE_EVENT(keepfast_recovery,
            TP_PROTO(struct segment_header_device *segdev, struct metablock_device *mbdev, int i),
            TP_ARGS(segdev, mbdev, i),

            TP_STRUCT__entry(
                    __field(u64,	segdev_id	     )
                    __field(u32,         oblock_packed_d                 )
                    __field(u32,	hit_count      	)
                    __field(u8,	        idx_packed_v	)
                             ),

            TP_fast_assign(
                    __entry->segdev_id		= segdev->global_id;
                    __entry->oblock_packed_d		= i;
                    __entry->hit_count	        = mbdev->hit_count;
                    __entry->idx_packed_v         = mbdev->idx_packed_v;
                           ),

            TP_printk("seg_id=%llu,  oblock_packed_d=%u hit_count=%d valid=%u",
                    (u64)__entry->segdev_id,
                    (u32)__entry->oblock_packed_d,
                    (u32)__entry->hit_count,
                    (u8)__entry->idx_packed_v
                      )
);
#endif
#endif /* _TRACE_KEEPFAST_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

