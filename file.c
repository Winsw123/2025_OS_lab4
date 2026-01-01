#include <linux/fs.h>
#include <linux/uaccess.h>
#include "osfs.h"

/**
 * Function: osfs_read
 * Description: Reads data from a file.
 * Inputs:
 *   - filp: The file pointer representing the file to read from.
 *   - buf: The user-space buffer to copy the data into.
 *   - len: The number of bytes to read.
 *   - ppos: The file position pointer.
 * Returns:
 *   - The number of bytes read on success.
 *   - 0 if the end of the file is reached.
 *   - -EFAULT if copying data to user space fails.
 */
/**
 * Function: osfs_get_block
 * Description: Maps a file's logical block index to a physical block number.
 *              Allocates blocks if necessary and allowed.
 */
static int osfs_get_block(struct osfs_inode *osfs_inode, struct osfs_sb_info *sb_info, uint32_t block_index, uint32_t *phys_block, int allocate)
{
    int ret;
    uint32_t *indirect_block;
    uint32_t *double_indirect_block;
    void *block_addr;

    // 1. Direct Blocks
    if (block_index < OSFS_DIRECT_BLOCKS) {
        if (osfs_inode->i_block[block_index] == 0) {
            if (!allocate) return -1; // Block not exists
            ret = osfs_alloc_data_block(sb_info, &osfs_inode->i_block[block_index]);
            if (ret) return ret;
            osfs_inode->i_blocks++;
        }
        *phys_block = osfs_inode->i_block[block_index];
        return 0;
    }

    block_index -= OSFS_DIRECT_BLOCKS;

    // 2. Indirect Blocks
    if (block_index < BLOCK_SIZE / sizeof(uint32_t)) {
        if (osfs_inode->i_block[OSFS_INDIRECT_BLOCK] == 0) {
            if (!allocate) return -1;
            ret = osfs_alloc_data_block(sb_info, &osfs_inode->i_block[OSFS_INDIRECT_BLOCK]);
            if (ret) return ret;
            osfs_inode->i_blocks++;
            
            // Initialize indirect block with 0
            block_addr = sb_info->data_blocks + osfs_inode->i_block[OSFS_INDIRECT_BLOCK] * BLOCK_SIZE;
            memset(block_addr, 0, BLOCK_SIZE);
        }

        block_addr = sb_info->data_blocks + osfs_inode->i_block[OSFS_INDIRECT_BLOCK] * BLOCK_SIZE;
        indirect_block = (uint32_t *)block_addr;

        if (indirect_block[block_index] == 0) {
            if (!allocate) return -1;
            ret = osfs_alloc_data_block(sb_info, &indirect_block[block_index]);
            if (ret) return ret;
            osfs_inode->i_blocks++;
        }
        *phys_block = indirect_block[block_index];
        return 0;
    }

    block_index -= BLOCK_SIZE / sizeof(uint32_t);

    // 3. Double Indirect Blocks
    // Calculate indices for double indirect block
    uint32_t pointers_per_block = BLOCK_SIZE / sizeof(uint32_t);
    uint32_t double_idx = block_index / pointers_per_block;
    uint32_t single_idx = block_index % pointers_per_block;

    if (double_idx < pointers_per_block) {
        // Double Indirect Block pointer in inode
        if (osfs_inode->i_block[OSFS_DOUBLE_INDIRECT_BLOCK] == 0) {
            if (!allocate) return -1;
            ret = osfs_alloc_data_block(sb_info, &osfs_inode->i_block[OSFS_DOUBLE_INDIRECT_BLOCK]);
            if (ret) return ret;
            osfs_inode->i_blocks++;
            
            // Zero out
            block_addr = sb_info->data_blocks + osfs_inode->i_block[OSFS_DOUBLE_INDIRECT_BLOCK] * BLOCK_SIZE;
            memset(block_addr, 0, BLOCK_SIZE);
        }

        // First level indirect block
        block_addr = sb_info->data_blocks + osfs_inode->i_block[OSFS_DOUBLE_INDIRECT_BLOCK] * BLOCK_SIZE;
        double_indirect_block = (uint32_t *)block_addr;

        if (double_indirect_block[double_idx] == 0) {
            if (!allocate) return -1;
            ret = osfs_alloc_data_block(sb_info, &double_indirect_block[double_idx]);
            if (ret) return ret;
            osfs_inode->i_blocks++;
            
            // Zero out
            block_addr = sb_info->data_blocks + double_indirect_block[double_idx] * BLOCK_SIZE;
            memset(block_addr, 0, BLOCK_SIZE);
        }

        // Physical data block
        block_addr = sb_info->data_blocks + double_indirect_block[double_idx] * BLOCK_SIZE;
        indirect_block = (uint32_t *)block_addr;

        if (indirect_block[single_idx] == 0) {
            if (!allocate) return -1;
            ret = osfs_alloc_data_block(sb_info, &indirect_block[single_idx]);
            if (ret) return ret;
            osfs_inode->i_blocks++;
        }
        
        *phys_block = indirect_block[single_idx];
        return 0;
    }

    return -EFBIG; // File too large
}

static ssize_t osfs_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
    struct inode *inode = file_inode(filp);
    struct osfs_inode *osfs_inode = inode->i_private;
    struct osfs_sb_info *sb_info = inode->i_sb->s_fs_info;
    void *data_block;
    ssize_t bytes_read = 0;
    uint32_t block_index;
    uint32_t offset_in_block;
    uint32_t phys_block;
    size_t chunk_len;
    int ret;

    if (*ppos >= osfs_inode->i_size)
        return 0;

    if (*ppos + len > osfs_inode->i_size)
        len = osfs_inode->i_size - *ppos;

    while (len > 0) {
        block_index = *ppos / BLOCK_SIZE;
        offset_in_block = *ppos % BLOCK_SIZE;
        
        ret = osfs_get_block(osfs_inode, sb_info, block_index, &phys_block, 0);
        if (ret < 0) {
            // Sparse file handling (reading unallocated block returns 0s)
             if (clear_user(buf, len))
                return -EFAULT;
             *ppos += len;
             bytes_read += len;
             break;
        }

        chunk_len = BLOCK_SIZE - offset_in_block;
        if (chunk_len > len)
            chunk_len = len;

        data_block = sb_info->data_blocks + phys_block * BLOCK_SIZE + offset_in_block;
        if (copy_to_user(buf, data_block, chunk_len))
            return -EFAULT;

        *ppos += chunk_len;
        buf += chunk_len;
        len -= chunk_len;
        bytes_read += chunk_len;
    }

    return bytes_read;
}

static ssize_t osfs_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
    struct inode *inode = file_inode(filp);
    struct osfs_inode *osfs_inode = inode->i_private;
    struct osfs_sb_info *sb_info = inode->i_sb->s_fs_info;
    void *data_block;
    ssize_t bytes_written = 0;
    uint32_t block_index;
    uint32_t offset_in_block;
    uint32_t phys_block;
    size_t chunk_len;
    int ret;

    while (len > 0) {
        block_index = *ppos / BLOCK_SIZE;
        offset_in_block = *ppos % BLOCK_SIZE;

        ret = osfs_get_block(osfs_inode, sb_info, block_index, &phys_block, 1);
        if (ret < 0) {
            if (ret == -EFBIG) return -EFBIG;
             return ret;
        }

        chunk_len = BLOCK_SIZE - offset_in_block;
        if (chunk_len > len)
            chunk_len = len;

        data_block = sb_info->data_blocks + phys_block * BLOCK_SIZE + offset_in_block;
        if (copy_from_user(data_block, buf, chunk_len))
            return -EFAULT;

        *ppos += chunk_len;
        buf += chunk_len;
        len -= chunk_len;
        bytes_written += chunk_len;
    }

    if (*ppos > osfs_inode->i_size) {
        osfs_inode->i_size = *ppos;
        inode->i_size = *ppos;
    }

    // Update modification time
    osfs_inode->__i_mtime = current_time(inode);
    mark_inode_dirty(inode);

    return bytes_written;
}

/**
 * Struct: osfs_file_operations
 * Description: Defines the file operations for regular files in osfs.
 */
const struct file_operations osfs_file_operations = {
    .open = generic_file_open, // Use generic open or implement osfs_open if needed
    .read = osfs_read,
    .write = osfs_write,
    .llseek = default_llseek,
    // Add other operations as needed
};

/**
 * Struct: osfs_file_inode_operations
 * Description: Defines the inode operations for regular files in osfs.
 * Note: Add additional operations such as getattr as needed.
 */
const struct inode_operations osfs_file_inode_operations = {
    // Add inode operations here, e.g., .getattr = osfs_getattr,
};
