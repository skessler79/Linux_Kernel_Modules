#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/list.h>

#define PROC_NAME "my_module"

struct my_data {
    char* input_data;
    struct list_head list;
};

static LIST_HEAD(my_data_list);

static ssize_t read_proc(struct file *file, char __user *buf, size_t size, loff_t *loff) {
    struct my_data *entry;
    ssize_t bytes_read = 0;
    ssize_t left = *loff;

    list_for_each_entry(entry, &my_data_list, list) {
        if(left > strlen(entry->input_data)){
            left -= strlen(entry->input_data);
            continue;
        }

        int bytes_to_read = min(strlen(entry->input_data) - left, size - bytes_read);
        if (bytes_to_read <= 0) {
            left -= strlen(entry->input_data);
            continue;
        }

        if (copy_to_user(buf + bytes_read, entry->input_data + left, bytes_to_read)) {
            return -EFAULT;
        }

        bytes_read += bytes_to_read;
        left = 0;
    }

    *loff += bytes_read;
    return bytes_read;
}


static ssize_t write_proc(struct file *file, const char __user *buf, size_t size, loff_t *loff) {
    struct my_data *data;
    char* input_data = kmalloc(size + 1, GFP_KERNEL);

    if (!input_data)
        return -ENOMEM;

    if (copy_from_user(input_data, buf, size)) {
        kfree(input_data);
        return -EFAULT;
    }

    input_data[size] = '\0';

    data = kmalloc(sizeof(*data), GFP_KERNEL);
    if (!data) {
        kfree(input_data);
        return -ENOMEM;
    }

    data->input_data = input_data;

    list_add_tail(&(data->list), &my_data_list);

    *loff += size;
    return size;
}

static const struct proc_ops my_module_fops = {
    .proc_read = read_proc,
    .proc_write = write_proc,
};

static int __init my_module_init(void) {
    return (proc_create(PROC_NAME, 0, NULL, &my_module_fops) == NULL) ? -ENOMEM : 0;
}

static void __exit my_module_exit(void) {
    struct my_data *data, *tmp;
    list_for_each_entry_safe(data, tmp, &my_data_list, list) {
        list_del(&(data->list));
        kfree(data->input_data);
        kfree(data);
    }

    remove_proc_entry(PROC_NAME, NULL);
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("My Name");
MODULE_DESCRIPTION("My Module Description without Mutex");