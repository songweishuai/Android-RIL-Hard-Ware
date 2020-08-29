/* //device/system/rild/rild.c
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <telephony/ril.h>
#define LOG_TAG "RILD"
#include <utils/Log.h>
#include <cutils/properties.h>
#include <cutils/sockets.h>
#include <linux/capability.h>
#include <linux/prctl.h>

#include <private/android_filesystem_config.h>
#include "hardware/qemu_pipe.h"

#define LIB_PATH_PROPERTY   "rild.libpath"
#define LIB_ARGS_PROPERTY   "rild.libargs"
#define MAX_LIB_ARGS        16

static void usage(const char *argv0)
{
    fprintf(stderr, "Usage: %s -l <ril impl library> [-- <args for impl library>]\n", argv0);
    exit(-1);
}

extern void RIL_register (const RIL_RadioFunctions *callbacks);

extern void RIL_onRequestComplete(RIL_Token t, RIL_Errno e,
                           void *response, size_t responselen);

extern void RIL_onUnsolicitedResponse(int unsolResponse, const void *data,
                                size_t datalen);

extern void RIL_requestTimedCallback (RIL_TimedCallback callback,
                               void *param, const struct timeval *relativeTime);


static struct RIL_Env s_rilEnv = {
    RIL_onRequestComplete,
    RIL_onUnsolicitedResponse,
    RIL_requestTimedCallback
};

extern void RIL_startEventLoop();

static int make_argv(char * args, char ** argv)
{
    // Note: reserve argv[0]
    int count = 1;
    char * tok;
    char * s = args;

    while ((tok = strtok(s, " \0"))) {
        argv[count] = tok;
        s = NULL;
        count++;
    }
    return count;
}

/*
 * switchUser - Switches UID to radio, preserving CAP_NET_ADMIN capabilities.
 * Our group, cache, was set by init.
 */
void switchUser() {
    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
    setuid(AID_RADIO);

    struct __user_cap_header_struct header;
    struct __user_cap_data_struct cap;
    header.version = _LINUX_CAPABILITY_VERSION;
    header.pid = 0;
    cap.effective = cap.permitted = (1 << CAP_NET_ADMIN) | (1 << CAP_NET_RAW);
    cap.inheritable = 0;
    capset(&header, &cap);
}


#define LOG_FILE_PATH "/data/rild.log"


int log_fd = -1 ;


int log_init(){

        int ret ;

        log_fd = open(LOG_FILE_PATH, O_RDWR|O_CREAT, S_IWUSR|S_IRUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) ;
        if(log_fd>0){
                ret = 0 ; 
        }else{

                ret = -1 ;
        }

        return ret ;
}


int log_out(char* debug_msg){

        int ret ;
        int msg_len ;

        if(log_fd<=0 || NULL==debug_msg){

                ret = -1 ;
        }else{

                msg_len = strlen(debug_msg) ;

                ret = write(log_fd, debug_msg, msg_len) ;
                if( ret != msg_len ){

                        ret = -1 ;
                }else{
                        ret = 0 ; 
                }
        }

        return ret ;
}


int main(int argc, char **argv)
{
    const char * rilLibPath = NULL;
    char **rilArgv;
    void *dlHandle;
    const RIL_RadioFunctions *(*rilInit)(const struct RIL_Env *, int, char **);
    const RIL_RadioFunctions *funcs;
    char libPath[PROPERTY_VALUE_MAX];
    unsigned char hasLibArgs = 0;

    int i;

	log_init() ;

    if ( 0 == property_get(LIB_PATH_PROPERTY, libPath, NULL)) {
		/* nothing to do */
	    log_out("nothing to do\n") ;
    } else {
        rilLibPath = libPath;
	    log_out("rilLibPath = libPath\n") ;
    }

    log_out("Debug001\n") ;

    umask(S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH);

    for (i = 1; i < argc ;) 
    {
	    log_out("Debug002\n") ;

        if (0 == strcmp(argv[i], "-l") && (argc - i > 1)) 
        {
		    log_out("Debug003\n") ;

        	if(rilLibPath == NULL){

			log_out("Debug004\n") ;
	            	rilLibPath = argv[i + 1];
        	}

		    log_out("Debug005\n") ;

        	i += 2;

        } 
        else if (0 == strcmp(argv[i], "--")) 
        {

	    log_out("Debug006\n") ;
            i++;
            hasLibArgs = 1;
            break;

        } 
        else 
        {
	        log_out("Debug007\n") ;
            usage(argv[0]);
        }
    }

    log_out("Debug008\n") ;

    if (rilLibPath == NULL) 
    {
    	log_out("err: get rilLibPath failed\n");
        log_out("Debug009\n") ;
		goto done;
    }

    log_out("Debug010\n") ;

    ALOGD("\nrilLibPath = %s\n\n", rilLibPath);

    //switchUser();

    log_out("Debug011\n") ;

    dlHandle = dlopen(rilLibPath, RTLD_NOW);

    if (dlHandle == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        ALOGE("dlopen failed: %s\n", dlerror());
        exit(-1);
    }

    RIL_startEventLoop();

    rilInit = (const RIL_RadioFunctions *(*)(const struct RIL_Env *, int, char **))dlsym(dlHandle, "RIL_Init");

    if (rilInit == NULL) {
        fprintf(stderr, "RIL_Init not defined or exported in %s\n", rilLibPath);
        exit(-1);
    }

    if (hasLibArgs) {
        rilArgv = argv + i - 1;
        argc = argc -i + 1;
    } else {
        static char * newArgv[MAX_LIB_ARGS];
        static char args[PROPERTY_VALUE_MAX];
        rilArgv = newArgv;
        property_get(LIB_ARGS_PROPERTY, args, "");
        argc = make_argv(args, rilArgv);
    }

    // Make sure there's a reasonable argv[0]
    rilArgv[0] = argv[0];

    funcs = rilInit(&s_rilEnv, argc, rilArgv);

    RIL_register(funcs);

done:

    while(1) {
        // sleep(UINT32_MAX) seems to return immediately on bionic
        sleep(1);
    }
}

