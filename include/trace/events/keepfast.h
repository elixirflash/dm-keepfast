#undef TRACE_SYSTEM
#define TRACE_SYSTEM keepfast

#if !defined(_TRACE_KEEPFAST_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KEEPFAST_H

//n#undef TRACE_SYSTEM
//#define TRACE_SYSTEM keepfast

#include <linux/tracepoint.h>

/* request.c */

TRACE_EVENT(keepfast_op,
            TP_PROTO(struct segment_header *seg, struct metablock *mb, int op),
            TP_ARGS(seg, mb, op),

            TP_STRUCT__entry(
                    __field(u32,	oblock_packed_d			)
                    __field(u64,	        seg_id      		)
                    __field(u32,	        hit_count      		)
                    __field(u8,	        idx_packed_v		)
                    __field(u8,	        op      		)
            ),

            TP_fast_assign(
                    __entry->seg_id		= seg->global_id;
                    __entry->oblock_packed_d		= mb->oblock_packed_d;
                    __entry->hit_count	        = mb->hit_count;
                    __entry->idx_packed_v     = mb->idx_packed_v;
                    __entry->op             = op;
            ),
            
            TP_printk("seg_id=%llu mb_id=%d sector=%llu op=%c",
                    (u64)__entry->seg_id,
                    (u32)__entry->oblock_packed_d,
                    (u64)__entry->hit_count,
                    (u32)__entry->op == 0 ? 'R' : \
                              (u32)__entry->op == 1 ? 'W' : \
                              (u32)__entry->op == 2 ? 'F' : \
                              (u32)__entry->op == 3 ? 'I' : \
                              (u32)__entry->op == 4 ? 'B' : 'X'
                      )
);

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

#endif /* _TRACE_KEEPFAST_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

