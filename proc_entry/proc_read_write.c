#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>

struct node
{
    char* message;
    struct list_head list;
};

static LIST_HEAD(node_list);

static ssize_t entry_proc_read(struct file* file, char __user *buf, size_t count, loff_t* pos)
{
    struct node* node;
    size_t total_size = 0;
    char* kernel_buf;
    char* current_pos;
    loff_t offset = *pos;
    
    kernel_buf = kmalloc(count, GFP_KERNEL);
    if(!kernel_buf)
        return -ENOMEM;
    memset(kernel_buf, 0, count);
    current_pos = kernel_buf;

    list_for_each_entry(node, &node_list, list)
    {
        // Skip entry based on offset
        if(offset)
        {
            --offset;
            continue;
        }

        size_t remaining_size = count - total_size;

        // Break on exceeding buffer size
        if(strlen(node->message) >= remaining_size)
            break;
        
        size_t len = snprintf(current_pos, remaining_size, "%s", node->message);
        current_pos += len;
        total_size += len;
    }

    // Copy from kernel buffer to user buffer
    if(copy_to_user(buf, kernel_buf, total_size))
    {
        kfree(kernel_buf);
        return -EFAULT;
    }
    
    *pos += total_size;

    kfree(kernel_buf);
    return total_size;
}

static ssize_t entry_proc_write(struct file* file, const char __user *buf, size_t count, loff_t* pos)
{
    struct node* new_node;
    new_node = kmalloc(sizeof(struct node), GFP_KERNEL);
    if(!new_node)
        return -ENOMEM;

    new_node->message = kmalloc(count, GFP_KERNEL);
    if(!new_node->message)
    {
        kfree(new_node);
        return -ENOMEM;
    }
    
    // Copy buffer from user space to kernel space
    if(copy_from_user(new_node->message, buf, count))
    {
        kfree(new_node->message);
        kfree(new_node);
        return -EFAULT;
    }
    new_node->message[count] = '\0';

    list_add_tail(&(new_node->list), &node_list);

    *pos += count;
    return count;
}

static const struct proc_ops ops =
{
    .proc_read = entry_proc_read,
    .proc_write = entry_proc_write,
};

static int proc_init(void)
{
    proc_create("selwyn", 0666, NULL, &ops);
    return 0;
}

static void proc_exit(void)
{
    struct node *node, *tmp;
    list_for_each_entry_safe(node, tmp, &node_list, list)
    {
        list_del(node);
        kfree(node->message);
        kfree(node);
    }
    remove_proc_entry("selwyn", NULL);
}

module_init(proc_init);
module_exit(proc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Selwyn");
MODULE_DESCRIPTION("proc read/write");