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
                    __field(sector_t,	sector			)
                    __field(u64,	        seg_id      		)
                    __field(u32,	        mb_id      		)  
                    __field(u8,	        dirty_bits		)
                    __field(u8,	        op      		)    
            ),

            TP_fast_assign(
                    __entry->seg_id		= seg->global_id;
                    __entry->mb_id		= mb->idx;
                    __entry->sector	= mb->sector;
                    __entry->dirty_bits     = mb->dirty_bits;
                    __entry->op             = op;
            ),
            
            TP_printk("seg_id=%llu mb_id=%d sector=%llu op=%c",
                    (u64)__entry->seg_id,
                    (u32)__entry->mb_id,
                    (u64)__entry->sector,
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
                    __field(u64,	segdev_id			)
                    __field(u32,	segdev_lap         	)
                    __field(u32,         mb_idx                 )
                    __field(sector_t,	sector      		)                             
                    __field(u8,	        dirty_bits		)
                    __field(u32,        mb_lap      		)    
            ),

            TP_fast_assign(
                    __entry->segdev_id		= segdev->global_id;
                    __entry->segdev_lap		= segdev->lap;
                    __entry->mb_idx		= i;
                    __entry->sector	        = mbdev->sector;
                    __entry->dirty_bits         = mbdev->dirty_bits;
                    __entry->mb_lap             = mbdev->lap
            ),
            
            TP_printk("seg_id=%llu, seg_lap=%u mb_id=%u sector=%llu dirty=%u mb_lap=%u",
                    (u64)__entry->segdev_id,
                    (u32)__entry->segdev_lap,    
                    (u32)__entry->mb_idx,
                    (sector_t)__entry->sector,
                    (u8)__entry->dirty_bits,
                    (u32)__entry->mb_lap
           )
);

#endif /* _TRACE_KEEPFAST_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

