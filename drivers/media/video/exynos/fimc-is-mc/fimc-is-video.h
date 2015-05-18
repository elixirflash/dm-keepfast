struct fimc_is_fmt *fimc_is_find_format(u32 *pixelformat,
	u32 *mbus_code, int index);
void fimc_is_set_plane_size(struct fimc_is_frame *frame,
	unsigned long sizes[]);
