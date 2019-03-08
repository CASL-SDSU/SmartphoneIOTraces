#ifndef MMC_QUEUE_H
#define MMC_QUEUE_H

/**********dzhou*****************************************************/
 struct record_structure{
    struct file *filep;
    struct mutex	record_lock;
    char * log_buff;
    char * file_dir;
    int buffer_sz;
    unsigned long total_sectors;
    unsigned long total_start;
    unsigned long total_end;
    unsigned long total_num;
    struct timespec last_flush;
    struct timespec curr_time;
    int time_out;
    int output_len;
    int pg_num_order;
    int flags;
    int rights;
    int offset;
    int overhead;
    int (*record_collect)(struct request*, struct record_time *, int, struct mmc_queue*);
    int (*record_start)(struct record_structure*,struct record_time *);
    int (*record_end)(struct record_structure*, struct record_time *);
};
/**********dzhou*****************************************************/
struct request;
struct task_struct;
struct mmc_blk_request {
	struct mmc_request	mrq;
	struct mmc_command	sbc;
	struct mmc_command	cmd;
	struct mmc_command	stop;
	struct mmc_data		data;
};

enum mmc_packed_cmd {
	MMC_PACKED_NONE = 0,
	MMC_PACKED_WRITE,
};

struct mmc_queue_req {
	struct request		*req;
	struct mmc_blk_request	brq;
	struct scatterlist	*sg;
	char			*bounce_buf;
	struct scatterlist	*bounce_sg;
	unsigned int		bounce_sg_len;
	struct mmc_async_req	mmc_active;
	struct list_head	packed_list;
	u32			packed_cmd_hdr[128];
	unsigned int		packed_blocks;
	enum mmc_packed_cmd	packed_cmd;
	int		packed_retries;
	int		packed_fail_idx;
	u8		packed_num;
};

struct mmc_queue {
	struct mmc_card		*card;
	struct record_structure record;
	struct task_struct	*thread;
	struct semaphore	thread_sem;
	unsigned int		flags;
#define MMC_QUEUE_SUSPENDED		(1 << 0)
#define MMC_QUEUE_NEW_REQUEST		(1 << 1)
#define MMC_QUEUE_URGENT_REQUEST	(1 << 2)

	int			(*issue_fn)(struct mmc_queue *, struct request *);
	void			*data;
	struct request_queue	*queue;
	struct mmc_queue_req	mqrq[2];
	struct mmc_queue_req	*mqrq_cur;
	struct mmc_queue_req	*mqrq_prev;
	bool			wr_packing_enabled;
	int			num_of_potential_packed_wr_reqs;
	int			num_wr_reqs_to_start_packing;
	bool			no_pack_for_random;
	int (*err_check_fn) (struct mmc_card *, struct mmc_async_req *);
	void (*packed_test_fn) (struct request_queue *, struct mmc_queue_req *);
};

extern int mmc_init_queue(struct mmc_queue *, struct mmc_card *, spinlock_t *,
			  const char *);
extern void mmc_cleanup_queue(struct mmc_queue *);
extern int mmc_queue_suspend(struct mmc_queue *, int);
extern void mmc_queue_resume(struct mmc_queue *);

extern unsigned int mmc_queue_map_sg(struct mmc_queue *,
				     struct mmc_queue_req *);
extern void mmc_queue_bounce_pre(struct mmc_queue_req *);
extern void mmc_queue_bounce_post(struct mmc_queue_req *);

extern void print_mmc_packing_stats(struct mmc_card *card);
extern void record_init(struct record_structure* record);
extern int record_collect_req(struct request* req, struct record_time *rt, int, struct mmc_queue*);
extern int record_start_req(struct record_structure*,struct record_time *);
extern int record_end_req(struct record_structure* record, struct record_time * rt);

#endif
