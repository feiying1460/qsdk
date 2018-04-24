#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sem.h>
#include <sys/ipc.h>

#include "uci_core.h"
#include "package.h"

#define DEBUG_PKG
#ifdef DEBUG_PKG
 #define DEBUG(args...) printf(args)
#else
 #define DEBUG(args...)
#endif

static struct pkgmgr_s pkgMgr = {NULL, 0, NULL, 0};

static int pkgLockInit(struct pkgmgr_s *pkgm)
{
    int semid;
    key_t key;
    union semun{
        int val;
    } semarg;

    if (pkgm->semid)
        return 0;
    
    key = ftok( "/proc/version", 127);
    if (key == -1)
        return -1;

    semid = semget(key, 0, 0);
    if (semid == -1)
    {
        semid = semget(key, 1, IPC_CREAT|IPC_EXCL|0666);
        if (semid == -1)
            return -1;

        semarg.val = 1;
        if (semctl(semid, 0, SETVAL, semarg) == -1)
        {
            semctl(semid, 0, IPC_RMID, semarg);
            return -1;
        }
    }

    pkgm->semid = semid;
    return 0;
}

static int pkgLock(struct pkgmgr_s *pkgm)
{
    struct sembuf sem;

    if (pkgLockInit(pkgm) == -1)
        return -1;

    sem.sem_num  = 0;
    sem.sem_op   = -1;
    sem.sem_flg  = SEM_UNDO;

    if (semop(pkgm->semid, &sem, 1) == -1)
    {
        return -1;
    }

    return 0;
} 

static int pkgUnlock(struct pkgmgr_s *pkgm)
{
    struct sembuf sem;

    if (pkgLockInit(pkgm) == -1)
        return -1;

    sem.sem_num  = 0;
    sem.sem_op   = 1;
    sem.sem_flg  = SEM_UNDO;

    if (semop(pkgm->semid, &sem, 1) == -1)
    {
        return -1;
    }

    return 0;
}

int pkgInit(struct pkgmgr_s *pkgm)
{
    int ret = 0;
    struct package_s *pkg = pkgm->head;

    DEBUG("Package Init\n");

    while(pkg)
    {
        if (pkg->init
            && pkg->init(pkg))
        {
            ret = -1;
            printf("libstorage: package[%s] initial failed\n", pkg->name);
        }
        pkg = pkg->next;
    }

    pkgm->cookie = (void *)uciInit();

    if (!pkgm->cookie)
    {
        printf("libstorage: UCI context initial failed\n");
        ret = -1;
    }

    return ret;
}


int pkgSet(struct pkgmgr_s *pkgm, char *name, char *value)
{
    int ret = 0;
    struct package_s *pkg = pkgm->head;

    DEBUG("Package Set %s:%s\n", name, value);
    while(pkg)
    {
        if ( (pkg->flt1 && memcmp(pkg->flt1, name, strlen(pkg->flt1)) == 0)
            || (pkg->flt2 && memcmp(pkg->flt2, name, strlen(pkg->flt2)) == 0)) 
        {
            ret = pkg->set(pkgm->cookie, pkg, name, value);
            break;
        }
        pkg = pkg->next;
    }

    if (!pkg)
    {
        printf("libstorage: unhandled optoin %s:%s\n", name, value);
    }
    else if (ret)
    {
        printf("libstorage: package[%s] set %s:%s failed\n", pkg->name, name, value);
        return -1;
    }

    return ret;
}

int pkgApply(struct pkgmgr_s *pkgm)
{
    int ret = 0;
    struct package_s *pkg = pkgm->head;

    DEBUG("Package Apply\n");

    /*lock to prevent parellel apply*/
    if (pkgLock(pkgm))
        DEBUG("Package lock failed\n");

    while(pkg)
    {
        if (pkg->apply 
            && pkg->apply(pkgm->cookie, pkg))
        {
            ret = -1;
            printf("libstorage: package[%s] apply failed\n", pkg->name);
        }
        pkg = pkg->next;
    }
    /*unlock*/
    if (pkgUnlock(pkgm))
        DEBUG("Package unlock failed\n");

    return ret;
}


int pkgDestroy(struct pkgmgr_s *pkgm)
{
    int ret = 0;
    struct package_s *pkg = pkgm->head;

    DEBUG("Package Destroy\n");
    while(pkg)
    {
        if (pkg->destroy
            &&  pkg->destroy(pkg))
        {
            ret = -1;
            printf("libstorage: package[%s] destroy failed\n", pkg->name);
        }
        pkg = pkg->next;
    }

    if (pkgm->cookie)
        uciDestroy(pkgm->cookie);
    pkgm->cookie = NULL;

    return ret;
}


int pkgRegister(struct package_s *pkg)
{
    struct package_s *ipkg = pkgMgr.head;

    DEBUG("register %s\n", pkg->name);
    while(ipkg)
    {
        if (strcmp (ipkg->name, pkg->name) == 0)
        {
            return 0;
        }
            
        ipkg = ipkg->next;
    }

    pkg->next = pkgMgr.head;
    pkgMgr.head = pkg;
    return 0;
}



struct pkgmgr_s *pkgGetPkgmgr()
{
    if (pkgMgr.isInit)
        return &pkgMgr;

    DEBUG("Package Register\n");

    extern int wsplc_register();
    wsplc_register();

    extern int hyfi_register();
    hyfi_register();

    extern int wireless_register();
    wireless_register();

    extern int plc_register();
    plc_register();

    pkgMgr.isInit = 1;
    return &pkgMgr;
}



