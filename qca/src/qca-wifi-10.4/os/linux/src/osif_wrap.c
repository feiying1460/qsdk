#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_bridge.h>
#include <linux/proc_fs.h>
#include <sys/queue.h>
#include "osif_private.h"
#include "osif_wrap_private.h"
#include "osif_wrap.h"
#include "if_athvar.h"


/**
 * @brief Calls hardstart to transmit buf.
 *
 * @param skb
 *
 * @return 0 on success
 * @return -ve on failure
 */
static int osif_wrap_dev_xmit(struct sk_buff *skb)
{
    if ((skb->len) > (skb->dev->mtu))
        kfree_skb(skb);
    else {
        skb_push(skb, ETH_HLEN);
        osif_vap_hardstart(skb,skb->dev);
    }
    return 0;
}

/**
 * @brief Find wrap dev object based on MAC address.
 *
 * @param wdt Ptr to the wrap device table.
 * @param mac MAC address to look up.
 *
 * @return osif_dev on success
 * @return NULL on failure
 */
osif_dev *osif_wrap_wdev_find(struct wrap_devt *wdt,unsigned char *mac)
{
    osif_dev *osdev;
    int hash;
    rwlock_state_t lock_state;

    hash = WRAP_DEV_HASH(mac);
    OS_RWLOCK_READ_LOCK(&wdt->wdt_lock,&lock_state);
    LIST_FOREACH(osdev, &wdt->wdt_hash[hash], osif_dev_hash) {
        if (IEEE80211_ADDR_EQ(osdev->osif_dev_oma, mac)){
            OS_RWLOCK_READ_UNLOCK(&wdt->wdt_lock,&lock_state);
            return osdev;
        }
    }
    OS_RWLOCK_READ_UNLOCK(&wdt->wdt_lock,&lock_state);
    return NULL;
}
EXPORT_SYMBOL(osif_wrap_wdev_find);
/**
 * @brief Find wrap dev object based on VMA MAC address.
 *
 * @param wdt Ptr to the wrap device table.
 * @param mac MAC address to look up.
 *
 * @return osif_dev on success
 * @return NULL on failure
 */
osif_dev *osif_wrap_wdev_vma_find(struct wrap_devt *wdt,unsigned char *mac)
{
    osif_dev *osdev;
    int hash;
    rwlock_state_t lock_state;

    hash = WRAP_DEV_HASH(mac);
    OS_RWLOCK_READ_LOCK(&wdt->wdt_lock,&lock_state);
    LIST_FOREACH(osdev, &wdt->wdt_hash_vma[hash], osif_dev_hash_vma) {
        if (IEEE80211_ADDR_EQ(osdev->osif_dev_vma, mac)){
            OS_RWLOCK_READ_UNLOCK(&wdt->wdt_lock,&lock_state);
            return osdev;
        }
    }
    OS_RWLOCK_READ_UNLOCK(&wdt->wdt_lock,&lock_state);
    return NULL;
}




/**
 * @brief Add wrap dev object to the device table, also
 * registers bridge hooks if this the first object.
 *
 * @param osdev Pointer to osif_dev to add.
 *
 * @return 0 on success
 * @return -ve on failure
 */
int osif_wrap_dev_add(osif_dev *osdev)
{
	int hash, hash_vma;
    wlan_if_t vap = osdev->os_if;
    struct wrap_devt *wdt = &vap->iv_ic->ic_wrap_com->wc_devt;
    struct wrap_com *wrap_com = vap->iv_ic->ic_wrap_com;
    rwlock_state_t lock_state;
    struct net_device *netdev = OSIF_TO_NETDEV(osdev);

    OSIF_WRAP_MSG("Adding %s to the list mat\n",OSIF_TO_DEVNAME(osdev));
    if(vap->iv_mat == 1) {
        IEEE80211_ADDR_COPY(osdev->osif_dev_oma,vap->iv_mat_addr);
	IEEE80211_ADDR_COPY(osdev->osif_dev_vma,netdev->dev_addr);
    }
    else {
        IEEE80211_ADDR_COPY(osdev->osif_dev_oma,netdev->dev_addr);
        IEEE80211_ADDR_COPY(osdev->osif_dev_vma,netdev->dev_addr);
    }

    hash = WRAP_DEV_HASH(osdev->osif_dev_oma);
    hash_vma = WRAP_DEV_HASH(osdev->osif_dev_vma);
    OS_RWLOCK_WRITE_LOCK(&wdt->wdt_lock,&lock_state);
    LIST_INSERT_HEAD(&wdt->wdt_hash[hash], osdev, osif_dev_hash);
    TAILQ_INSERT_TAIL(&wdt->wdt_dev, osdev, osif_dev_list);
    LIST_INSERT_HEAD(&wdt->wdt_hash_vma[hash_vma], osdev, osif_dev_hash_vma);
    TAILQ_INSERT_TAIL(&wdt->wdt_dev_vma, osdev, osif_dev_list_vma);
    osdev->wrap_handle = wrap_com;
    if(wrap_com->wc_isolation)
        vap->iv_isolation = 1;
    else
        vap->iv_isolation = 0;
    wdt->wdt_dev_cnt++;
    wdt->wdt_dev_cnt_vma++;
    OS_RWLOCK_WRITE_UNLOCK(&wdt->wdt_lock,&lock_state);
    return 0;
}

/**
 * @brief Delete wrap dev object from the device table, also
 * unregisters bridge hooks if this the last object.
 *
 * @param osdev Ptr to the osif_dev to delete
 *
 * @return void
 */
void osif_wrap_dev_remove(osif_dev *osdev)
{
    int hash;
    osif_dev *osd;
    wlan_if_t vap = osdev->os_if;
    struct wrap_devt *wdt = &vap->iv_ic->ic_wrap_com->wc_devt;
    rwlock_state_t lock_state;
    hash = WRAP_DEV_HASH(osdev->osif_dev_oma);
    OS_RWLOCK_WRITE_LOCK(&wdt->wdt_lock,&lock_state);
    LIST_FOREACH(osd, &wdt->wdt_hash[hash], osif_dev_hash) {
        if (IEEE80211_ADDR_EQ(osd->osif_dev_oma,osdev->osif_dev_oma)){
            LIST_REMOVE(osd,osif_dev_hash);
	    TAILQ_REMOVE(&wdt->wdt_dev, osd, osif_dev_list);
	    OSIF_WRAP_MSG("Removing %s from the list\n",OSIF_TO_DEVNAME(osdev));
	    wdt->wdt_dev_cnt--;
	    OS_RWLOCK_WRITE_UNLOCK(&wdt->wdt_lock,&lock_state);
	    return;
	}
    }
    OS_RWLOCK_WRITE_UNLOCK(&wdt->wdt_lock,&lock_state);
    return;
}

/**
 * @brief Delete wrap dev object from the vma device table
 * @param osdev Ptr to the osif_dev to delete
 * @return void
 */
void osif_wrap_dev_remove_vma(osif_dev *osdev)
{
    int hash;
    osif_dev *osd;
    wlan_if_t vap = osdev->os_if;
    struct wrap_devt *wdt = &vap->iv_ic->ic_wrap_com->wc_devt;
    rwlock_state_t lock_state;

    hash = WRAP_DEV_HASH(osdev->osif_dev_vma);
    OS_RWLOCK_WRITE_LOCK(&wdt->wdt_lock,&lock_state);
    LIST_FOREACH(osd, &wdt->wdt_hash_vma[hash], osif_dev_hash_vma) {
        if (IEEE80211_ADDR_EQ(osd->osif_dev_vma,osdev->osif_dev_vma)){
            LIST_REMOVE(osd,osif_dev_hash_vma);
            TAILQ_REMOVE(&wdt->wdt_dev_vma, osd, osif_dev_list_vma);
            OSIF_WRAP_MSG("Removing %s from VMA list\n",OSIF_TO_DEVNAME(osdev));
            wdt->wdt_dev_cnt_vma--;
            OS_RWLOCK_WRITE_UNLOCK(&wdt->wdt_lock,&lock_state);
            return;
        }
    }
    OS_RWLOCK_WRITE_UNLOCK(&wdt->wdt_lock,&lock_state);
    return;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
int osif_wrap_proc_write(struct file *file, const char *buffer, unsigned long count, void *data)
#else
int osif_wrap_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos)
#endif
{
    char buf[4];

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    struct wrap_com *wc=(struct wrap_com*)data;
#else
    struct wrap_com *wc = PDE_DATA(file_inode(file));
#endif
    u_int32_t arg,cmd;

    if ((count > sizeof(buf)) || (count < sizeof(buf))) {
        QDF_PRINT_INFO(QDF_PRINT_IDX_SHARED, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, "Isolation not set, use this cmd and format: echo '1 1' > /proc/wrapx");
        return -EINVAL;
    }

    if (copy_from_user(buf,buffer,sizeof(buf))) {
        return -EFAULT;
    }
    buf[sizeof(buf)-1]='\0';
    cmd = (u_int32_t)simple_strtoul(&buf[OSIF_WRAP_PROC_CMD_OFFSET],NULL,10);
    arg = (u_int32_t)simple_strtoul(&buf[OSIF_WRAP_PROC_ARG_OFFSET],NULL,10);
    switch (cmd) {
        case WRAP_PROC_CMD_ISOLATION:
	    if(arg == 1)
	        wc->wc_isolation = 1;
	    else
	        wc->wc_isolation = 0;
	    OSIF_WRAP_MSG("WRAP isolation %d\n",wc->wc_isolation);
	    break;
	default:
	    OSIF_WRAP_MSG("Invalid cmd\n");
	    return -EINVAL;
	    break;
    }

    return(count);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
int osif_wrap_proc_read(char *buf, char **start, off_t offset, int count, int *eof, void *data)
#else
int osif_wrap_proc_read(struct seq_file *m, void *v)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct wrap_com *wc=(struct wrap_com*)data;
#else
	struct wrap_com *wc=(struct wrap_com*)m->private;
#endif
    struct wrap_devt *wdt = &wc->wc_devt;
    osif_dev *osd;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)) || not_yet
    int len=0;
#endif
    struct net_device *netdev;
#if not_yet
	int type=-1;
#endif

    if(TAILQ_EMPTY(&wdt->wdt_dev))
        return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    len += snprintf(buf + len, (PAGE_SIZE - len), "Isolation is %s\n",
               (wc->wc_isolation == 1) ? "enabled" : "disabled");
    len += snprintf(buf + len, (PAGE_SIZE - len), "%-4s [ type][%-17s] [d:o:s]\n",
               "dev", "oma");
#else
    seq_printf(m, "Isolation is %s\n",(wc->wc_isolation==1)?"enabled":"disabled");
	seq_printf(m,"%-4s [ type][%-17s] [d:o:s]\n","dev","oma");
#endif

    TAILQ_FOREACH(osd, &wdt->wdt_dev, osif_dev_list) {
        netdev = OSIF_TO_NETDEV(osd);
#if not_yet
        if(netdev->br_port)
            type  = br_get_port_type(netdev->br_port);
         len += sprintf(buf+len,"%s [%d][%s] [%lu:%lu:%lu]\n",
	 OSIF_TO_DEVNAME(osd),type,
	 ether_sprintf(osd->osif_dev_oma),
	 osd->osif_dev_cnt_drp,osd->osif_dev_cnt_ovrd,
	 osd->osif_dev_cnt_stl);
#endif
   }
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    if(len <= count + offset )
        *eof = 1;
    *start = buf + offset;
    len -= offset;

    if(len > count )
        len = count;
    if(len < 0 )
        len = 0;

    return len;
#else
    return 0;
#endif
}

/**
 * @brief WRAP proc fs init
 *
 * @param wc Ptr to the wrap common.
 *
 * @return void
 */
#if !(LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0))
static int osif_wrap_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, osif_wrap_proc_read, PDE_DATA(inode));
}

static const struct file_operations ath_wrap_fops = {
    .open       = osif_wrap_proc_open,
    .write      = osif_wrap_proc_write,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = seq_release,
};
#endif
static void osif_wrap_proc_init(struct wrap_com *wc, struct ieee80211com *ic)
{
    struct proc_dir_entry *proc_entry = wc->wc_proc_entry;
    char tmp[WRAP_PROC_MAX_FILE_LENGTH], *tmp1;
    struct net_device *dev = ic->ic_osdev->netdev;
    unsigned int proc_idx = 0;

    tmp1 = OS_MALLOC(NULL,sizeof(char)*WRAP_PROC_MAX_FILE_LENGTH, GFP_KERNEL);
    if (!tmp1) {
        OSIF_WRAP_MSG_ERR("Failed to alloc mem for wrap proc entry \n");
        return;
    }
    OS_MEMZERO(tmp1, WRAP_PROC_MAX_FILE_LENGTH);
    proc_idx = (u_int32_t)(dev->name[strlen(dev->name)-1]-'0');
    snprintf(tmp, sizeof(tmp),
              WRAP_PROC_FILE "%d", proc_idx);

    if (strlen(tmp) >= WRAP_PROC_MAX_FILE_LENGTH) {
        OSIF_WRAP_MSG_ERR("Length of the filename exceeds maximum length allowed \n");
        OS_FREE(tmp1);
        return;
    }
    OS_MEMCPY(tmp1,tmp,strlen(tmp)+1);

    if (tmp1)
        wc->wc_proc_name = tmp1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    proc_entry = create_proc_entry(wc->wc_proc_name, WRAP_PROC_PERM, NULL);
    if (proc_entry) {
        proc_entry->nlink = 1;
        proc_entry->data = (void *)(wc);
        proc_entry->read_proc = osif_wrap_proc_read;
        proc_entry->write_proc = osif_wrap_proc_write;
    }
#else
    proc_entry = proc_create_data(wc->wc_proc_name, WRAP_PROC_PERM, NULL,
                    &ath_wrap_fops, (void *)(wc));
#endif
    return;
}

/**
 * @brief WRAP proc fs remove
 *
 * @param wc Ptr to the wrap common.
 *
 * @return void
 */
static void osif_wrap_proc_remove(struct wrap_com *wc)
{

    if(wc->wc_proc_name) {
        remove_proc_entry(wc->wc_proc_name,NULL);
        OS_FREE((char *)wc->wc_proc_name);
    }
    return;
}

/**
 * @brief WRAP device table attach
 *
 * @param wc Ptr to the wrap common.
 * @param wdt Ptr to wrap device table.
 *
 * @return void
 */
static void osif_wrap_devt_init(struct wrap_com *wc, struct wrap_devt *wdt, struct ieee80211com *ic)
{
    int i;

    OS_RWLOCK_INIT(&wdt->wdt_lock);
    TAILQ_INIT(&wdt->wdt_dev);
    TAILQ_INIT(&wdt->wdt_dev_vma);
    for(i=0;i<WRAP_DEV_HASHSIZE;i++) {
        LIST_INIT(&wdt->wdt_hash[i]);
        LIST_INIT(&wdt->wdt_hash_vma[i]);
    }
    wdt->wdt_wc=wc;
    osif_wrap_proc_init(wc, ic);
    OSIF_WRAP_MSG("osif wrap dev table init done\n");
    return;
}

/**
 * @brief wrap device table detach
 *
 * @param wrap comm
 *
 * @return
 */
static void osif_wrap_devt_detach(struct wrap_com *wc)
{
    struct wrap_devt *wdt = &wc->wc_devt;
    osif_wrap_proc_remove(wc);
    OS_RWLOCK_DESTROY(&wdt->wdt_lock);
    wdt->wdt_wc=NULL;
    OSIF_WRAP_MSG("osif wrap dev table detached\n");
    return;
}

/**
 * @brief wrap attach
 *
 * @param void
 *
 * @return 0 on success
 * @return -ve on failure
 */
int osif_wrap_attach(wlan_dev_t ic)
{
    int ret=0;
    struct wrap_com *wrap_com ;

    wrap_com = OS_MALLOC(NULL,sizeof(struct wrap_com),GFP_KERNEL);
    if (!wrap_com) {
        OSIF_WRAP_MSG_ERR("Failed to alloc mem for wrap common\n");
     	return -EINVAL;
    } else{
        OSIF_WRAP_MSG("osif wrap attached\n");
    }
    OS_MEMZERO(wrap_com,sizeof(struct wrap_com));
    wrap_com->wc_use_cnt++;
    osif_wrap_devt_init(wrap_com, &wrap_com->wc_devt, ic);
    ic->ic_wrap_com=wrap_com;
    osif_wrap_reinit(ic);
    QDF_PRINT_INFO(ic->ic_print_idx, QDF_MODULE_ID_ANY, QDF_TRACE_LEVEL_INFO, " Wrap Attached: Wrap_com =%p ic->ic_wrap_com=%p &wrap_com->wc_devt=%p \n", wrap_com, ic->ic_wrap_com, &wrap_com->wc_devt);
    return ret;
}

/**
 * @brief wrap detach
 *
 * @param void
 *
 * @return 0 on success
 * @return -ve on failure
 */
int osif_wrap_detach(wlan_dev_t ic)
{
    int ret=0;
    struct wrap_com *wrap_com = ic->ic_wrap_com;

    ASSERT(wrap_com != NULL);

    wrap_com->wc_use_cnt--;
    if(wrap_com->wc_use_cnt==0){
        osif_wrap_devt_detach(wrap_com);
	OS_FREE(wrap_com);
	ic->ic_wrap_com = NULL;
	OSIF_WRAP_MSG("osif wrap detached\n");
    }
    return ret;
}

/**
 * @brief wrap reinit
 *
 * @param ic
 *
 */
void osif_wrap_reinit(wlan_dev_t ic)
{
    struct wrap_com *wrap_com = ic->ic_wrap_com;

    ASSERT(wrap_com != NULL);
#define WRAP_ISOLATION_DEFVAL 0
    wrap_com->wc_isolation = WRAP_ISOLATION_DEFVAL;
}
