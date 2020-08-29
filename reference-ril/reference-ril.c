/* //device/system/reference-ril/reference-ril.c
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

#include <telephony/ril_cdma_sms.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <alloca.h>
#include "atchannel.h"
#include "at_tok.h"
#include "misc.h"
#include <getopt.h>
#include <sys/socket.h>
#include <cutils/sockets.h>
#include <termios.h>
#include <sys/system_properties.h>

#include "ril.h"
#include "hardware/qemu_pipe.h"

#define LOG_TAG "RIL"
#include <utils/Log.h>


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>


#define LOG_FILE_PATH "/data/log.txt"

/*
 * 
 */


static RIL_RadioState sState = RADIO_STATE_ON ;

static int csq = 0 ;

static int query ;



/*** Callback methods from the RIL library to us ***/

/**
 * Call from RIL to us to make a RIL_REQUEST
 *
 * Must be completed with a call to RIL_onRequestComplete()
 *
 * RIL_onRequestComplete() may be called from any thread, before or after
 * this function returns.
 *
 * Will always be called from the same thread, so returning here implies
 * that the radio is ready to process another command (whether or not
 * the previous command has completed).
 */


int log_fd = -1 ;


pthread_mutex_t read_thread_mtx = PTHREAD_MUTEX_INITIALIZER ;
pthread_cond_t  read_thread_cond  = PTHREAD_COND_INITIALIZER ;


#if 0

int sockfd = 0 ;

int log_init(){

	int ret ;
	struct sockaddr_in serv_addr;

	/*
	log_fd = open(LOG_FILE_PATH, O_RDWR|O_CREAT, S_IWUSR|S_IRUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) ;
	if(log_fd>0){
		ret = 0 ;
	}else{

		ret = -1 ;
	}

	return ret ;
	*/

	sockfd = socket(AF_INET, SOCK_STREAM, 0) ;
	if(sockfd<0){
		goto error_001 ;
	}

	
	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(9900);

	if( inet_pton(AF_INET, "192.168.0.117", &serv_addr.sin_addr)<=0 ){
		printf("\n inet_pton error occured\n");
		goto error_002 ;
	}


	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
		printf("\n Error : Connect Failed \n");
		goto error_003 ;
	}

	return 0 ;

error_003:

error_002:

error_001:

	sockfd = 0 ;

	return -1 ;
}


int log_out(char* debug_msg){

	int ret ;
	int msg_len ;

	/*

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

	*/

	if(0!=sockfd){
	
		ret = write(sockfd, debug_msg, strlen(debug_msg)) ;
		if(ret<=0){
			sockfd = 0 ;
			return -1 ;
		}

		return 0 ;	
	}

	ret = log_init() ;

	return ret ;
}

#else


int log_init(){

	return 0 ;
}


int log_out(char* dmesg){

	printf("%s\n", dmesg) ;
	return 0 ;
}


#endif




static void request_voice_registration_state(void *data, size_t datalen, RIL_Token t){

	int response[4];
	char* responseStr[4];


	log_out("request:RIL_REQUEST_VOICE_REGISTRATION_STATE\n") ;
			
	response[0] = 1;
	response[1] = 0xD509;
	response[2] = 0x80D413D;
	response[3] = RADIO_TECH_LTE;


	asprintf(&responseStr[0], "%d", response[0]);
	asprintf(&responseStr[1], "%x", response[1]);
	asprintf(&responseStr[2], "%x", response[2]);
	asprintf(&responseStr[3], "%d", response[3]);

	RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, 4*sizeof(char*));

}



static void request_data_registration_state(void *data, size_t datalen, RIL_Token t){

	int response[3];
	char* responseStr[3];


	log_out("request:RIL_REQUEST_DATA_REGISTRATION_STATE\n") ;
			
	response[0] = 1;
	response[1] = 0xD509;
	response[2] = 0x80D413D;


	asprintf(&responseStr[0], "%d", response[0]);
	asprintf(&responseStr[1], "%x", response[1]);
	asprintf(&responseStr[2], "%x", response[2]);

	property_set("net.gprs.gprsState", "1");
	RIL_onRequestComplete(t, RIL_E_SUCCESS, responseStr, 3*sizeof(char*));

}






static void requestOperator(void *data, size_t datalen, RIL_Token t){


	char *response[3];

	memset(response, 0, sizeof(response));

	response[0] = "CHN-UNICOM" ;
	response[1] = "UNICOM" ;
	response[2] = "46001" ;

	RIL_onRequestComplete(t, RIL_E_SUCCESS, response, sizeof(response));

	return ;
}




static int getCardStatus(RIL_CardStatus_v6 **pp_card_status) {

	RIL_CardState card_state;
    	int num_apps;

	log_out("getCardStatus() be called\n") ;

	static RIL_AppStatus app_status_array[] = {
	        // SIM_ABSENT = 0
        	{ RIL_APPTYPE_UNKNOWN, RIL_APPSTATE_UNKNOWN, RIL_PERSOSUBSTATE_UNKNOWN,
          	NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        	// SIM_NOT_READY = 1
        	{ RIL_APPTYPE_SIM, RIL_APPSTATE_DETECTED, RIL_PERSOSUBSTATE_UNKNOWN,
          	NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        	// SIM_READY = 2
        	{ RIL_APPTYPE_SIM, RIL_APPSTATE_READY, RIL_PERSOSUBSTATE_READY,
          	NULL, NULL, 0, RIL_PINSTATE_UNKNOWN, RIL_PINSTATE_UNKNOWN },
        	// SIM_PIN = 3
        	{ RIL_APPTYPE_SIM, RIL_APPSTATE_PIN, RIL_PERSOSUBSTATE_UNKNOWN,
          	NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED, RIL_PINSTATE_UNKNOWN },
        	// SIM_PUK = 4
        	{ RIL_APPTYPE_SIM, RIL_APPSTATE_PUK, RIL_PERSOSUBSTATE_UNKNOWN,
        	  NULL, NULL, 0, RIL_PINSTATE_ENABLED_BLOCKED, RIL_PINSTATE_UNKNOWN },
        	// SIM_NETWORK_PERSONALIZATION = 5
        	{ RIL_APPTYPE_SIM, RIL_APPSTATE_SUBSCRIPTION_PERSO, RIL_PERSOSUBSTATE_SIM_NETWORK,
        	  NULL, NULL, 0, RIL_PINSTATE_ENABLED_NOT_VERIFIED, RIL_PINSTATE_UNKNOWN }
    		};

	RIL_CardStatus_v6 *p_card_status = malloc(sizeof(RIL_CardStatus_v6));

	card_state = RIL_CARDSTATE_PRESENT;
        num_apps = 1;

	// Allocate and initialize base card status.
    	p_card_status->card_state = card_state = RIL_CARDSTATE_PRESENT;
    	p_card_status->universal_pin_state = RIL_PINSTATE_UNKNOWN;
    	p_card_status->gsm_umts_subscription_app_index = RIL_CARD_MAX_APPS;
    	p_card_status->cdma_subscription_app_index = RIL_CARD_MAX_APPS;
    	p_card_status->ims_subscription_app_index = RIL_CARD_MAX_APPS;
    	p_card_status->num_applications = num_apps;

	 // Initialize application status
    	int i;
    	for (i = 0; i < RIL_CARD_MAX_APPS; i++) {
        	p_card_status->applications[i] = app_status_array[0];
    	}

	// Pickup the appropriate application status
    	// that reflects sim_status for gsm.
    	if (num_apps != 0) {
        	// Only support one app, gsm
        	p_card_status->num_applications = 1;
        	p_card_status->gsm_umts_subscription_app_index = 0;

        	// Get the correct app status
       		p_card_status->applications[0] = app_status_array[2];
    	}

    	*pp_card_status = p_card_status;
    	return RIL_E_SUCCESS;
}



/**
 * Free the card status returned by getCardStatus
 */
static void freeCardStatus(RIL_CardStatus_v6 *p_card_status) {

	log_out("freeCardStatus() be called\n") ;
	free(p_card_status);
}



static void request_setup_data_call(void *data, size_t datalen, RIL_Token t){

	RIL_Data_Call_Response_v6 responses ;

	log_out("request:RIL_REQUEST_SETUP_DATA_CALL\n") ;

	responses.status = 0; 
	responses.suggestedRetryTime = -1;
	responses.cid = 1; 
	responses.active = 2; 
	responses.type = (char*)"PPP";
	responses.ifname = "ttyUSB0";
	responses.addresses = "192.168.108.131";
	responses.dnses = "10.0.1.1";
	responses.gateways = "10.0.1.1";

	RIL_onRequestComplete(t, RIL_E_SUCCESS, &responses, sizeof(RIL_Data_Call_Response_v6));

	property_set("net.gprs.gprsState", "1");
}



static void request_network_selection_mode(void *data, size_t datalen, RIL_Token t){

	int response = 0 ;

	RIL_onRequestComplete(t, RIL_E_SUCCESS, &response, sizeof(int));

	return ;
}



static void request_baseband_version(void *data, size_t datalen, RIL_Token t){

	char *line = "v2.2.1" ;

	RIL_onRequestComplete(t, RIL_E_SUCCESS, line, sizeof(char *));

	return ;
}



static void request_query_sim_lock(void *data, size_t datalen, RIL_Token t){

	int status = 0 ;

	RIL_onRequestComplete(t, RIL_E_SUCCESS, &status, sizeof(int *));

	return ;
}



static void request_signal_strength(void *data, size_t datalen, RIL_Token t){

	RLOGD("*****************************************************");
	RLOGD("*****************************************************");
	RLOGD("*****************************************************");
	RLOGD("*****************************************************");
	RLOGD("songweishuai request_signal_strength begin");
	RLOGD("*****************************************************");
	RLOGD("*****************************************************");
	RLOGD("*****************************************************");
	RLOGD("*****************************************************");
	RLOGD("*****************************************************");
	
	RIL_SignalStrength_v6 signalStrength;

    memset(&signalStrength, 0, sizeof(RIL_SignalStrength_v6));

	//#if ((PLATFORM_VERSION >= 420) || ((PLATFORM_VERSION < 100) && (PLATFORM_VERSION >= 42)))
#if (RIL_VERSION >= 7)
	signalStrength.LTE_SignalStrength.signalStrength = 99;
	signalStrength.LTE_SignalStrength.rsrp = 0x7FFFFFFF;
	signalStrength.LTE_SignalStrength.rsrq = 0x7FFFFFFF;
	signalStrength.LTE_SignalStrength.rssnr = 0x7FFFFFFF;
	signalStrength.LTE_SignalStrength.cqi = 0x7FFFFFFF;
#else
	signalStrength.LTE_SignalStrength.signalStrength = -1;
	signalStrength.LTE_SignalStrength.rsrp = -1;
	signalStrength.LTE_SignalStrength.rsrq = -1;
	signalStrength.LTE_SignalStrength.rssnr = -1;
	signalStrength.LTE_SignalStrength.cqi = -1;
#endif
	//signalStrength.GW_SignalStrength.signalStrength = 28;
	signalStrength.GW_SignalStrength.signalStrength = csq;
	signalStrength.GW_SignalStrength.bitErrorRate = 99;
	RIL_onRequestComplete(t, RIL_E_SUCCESS, &signalStrength, sizeof(RIL_SignalStrength_v6));
}


static void request_sim_state(void *data, size_t datalen, RIL_Token t){

	int result ;
	RIL_CardStatus_v6 *p_card_status;
	char *p_buffer;
	int buffer_size;

	log_out("request:RIL_REQUEST_GET_SIM_STATUS\n") ;

	result = getCardStatus(&p_card_status);
	if (result == RIL_E_SUCCESS) {
		p_buffer = (char *)p_card_status;
		buffer_size = sizeof(*p_card_status);
	} else {
		p_buffer = NULL;
		buffer_size = 0; 
	}

    RIL_onRequestComplete(t, result, p_buffer, buffer_size);
	freeCardStatus(p_card_status);

	return ;
}



static void onRequest (int request, void *data, size_t datalen, RIL_Token t){


	char log_msg[64] ;

	sprintf(log_msg, "Get request:%d\n", request) ;
	//RLOGD("***onRequest***:%s\n",log_msg);

	switch(request){

		case RIL_REQUEST_RADIO_POWER: /* 23 */

			//log_out("request:RIL_REQUEST_RADIO_POWER\n") ;

			RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
			break ;

		case RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE: /* 73 */

			//log_out("request:RIL_REQUEST_SET_PREFERRED_NETWORK_TYPE\n") ;

			RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
			break ;

		case RIL_REQUEST_SCREEN_STATE: /* 61 */
			
			//log_out("request:RIL_REQUEST_SCREEN_STATE\n") ;

			RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0);
			break ;

		case RIL_REQUEST_GET_SIM_STATUS: /* 1 */

			request_sim_state(data, datalen, t) ;
			break;


		
		// case RIL_REQUEST_GET_CURRENT_CALLS: /* 9 */
		
		// 	break ;


		case RIL_REQUEST_OPERATOR: /* 22 */

			requestOperator(data, datalen, t) ;

			break ;


		case RIL_REQUEST_VOICE_REGISTRATION_STATE: /* 20 */

			request_voice_registration_state(data, datalen, t) ;
			break ;

		case RIL_REQUEST_DATA_REGISTRATION_STATE: /* 21 */

			request_data_registration_state(data, datalen, t) ;
			break ;

		case RIL_REQUEST_QUERY_NETWORK_SELECTION_MODE: /* 45 */

			request_network_selection_mode(data, datalen, t) ;
			break ;

		case RIL_REQUEST_BASEBAND_VERSION: /* 51 */

			request_baseband_version(data,datalen,t) ;
			break ;


		case RIL_REQUEST_GET_IMEI: /* 38 */

			RIL_onRequestComplete(t, RIL_E_SUCCESS, "355189036244202", sizeof(char *));
			break ;


		case RIL_REQUEST_GET_IMEISV: /* 39 */

			RIL_onRequestComplete(t, RIL_E_SUCCESS, (void *)00, sizeof(char *));
			break ;

		case RIL_REQUEST_QUERY_FACILITY_LOCK: /* 42 */

			request_query_sim_lock(data, datalen, t) ;
			break ;

		case RIL_REQUEST_GET_IMSI: /* 11 */

			RIL_onRequestComplete(t, RIL_E_SUCCESS, "460023210226023",sizeof(char *));
			break ;

		//case RIL_REQUEST_SIM_IO: /* 28 */
		//	request_sim_io(data, datalen, t) ;
		//	break ;

		case RIL_REQUEST_SIGNAL_STRENGTH: /* 19 */
			request_signal_strength(data, datalen, t) ;
			break ;

		case RIL_REQUEST_SETUP_DATA_CALL:

			request_setup_data_call(data, datalen, t) ;
			break ;

		case RIL_REQUEST_DEACTIVATE_DATA_CALL:

			//log_out("request:RIL_REQUEST_DEACTIVATE_DATA_CALL\n") ;

			RIL_onRequestComplete(t, RIL_E_SUCCESS, NULL, 0) ;
			break ;
		default:
			//log_out("request match the 'default'\n") ;

			RIL_onRequestComplete(t, RIL_E_REQUEST_NOT_SUPPORTED, NULL, 0);
	}

}


/**
 * Synchronous call from the RIL to us to return current radio state.
 * RADIO_STATE_UNAVAILABLE should be the initial state.
 */
static RIL_RadioState currentState(){

	log_out("currentState() be called...\n") ;

	return sState;
}



/**
 * Call from RIL to us to find out whether a specific request code
 * is supported by this implementation.
 *
 * Return 1 for "supported" and 0 for "unsupported"
 */

static int onSupports (int requestCode){
    //@@@ todo

	log_out("onSupports() be called...\n") ;

	return 1;
}


static void onCancel (RIL_Token t)
{
	//@@@todo
	log_out("onCancel() be called...\n") ;
}



static const char* getVersion(void)
{
	log_out("getVersion() be called...\n") ;
	return "android reference-ril 1.0";
}




static const RIL_RadioFunctions s_callbacks = {
    RIL_VERSION,
    onRequest,
    currentState,
    onSupports,
    onCancel,
    getVersion
};

/**************************************************************************
char read_buf[AT_MAX_RESPONSE_LEN] ;


char* find_line_end(){

	char* p ;

	p = rest_head ;

	while(p!='\r' && p!='\n' && p!='\0'){

		p = p + 1 ;
	}

	return (*p =='\0') ? NULL : p ;
}


int my_read_line(char* line_buf ){

	p = find_line_end() ;
	if(p==NULL){

		
	}
}



static void* read_thread(void* param){

	int ret ;

	char line_buf[AT_MAX_RESPONSE_LEN] ;

	while(1){

		memset(line_buf, 0, sizeof(line_buf)) ;

		ret = my_read_line(line_buf) ;
		if(ret<0){

			printf("Error:call my_read_line() fail!\n") ;

			break ;
		}

		ret = process_line(line_buf) ;
		if(ret<0){
			printf("Error:call process_line() fail!\n") ;
		}

	}

	pthread_mutex_lock(&read_thread_mtx) ;
	pthread_cond_signal(&read_thread_cond) ;
	pthread_mutex_unlock(&read_thread_mtx) ;

	return NULL ;
}
****************************************************************************/

/* 将file_name中的命令写进串口中，命令存在cmd_buffer中，*/

pthread_t tid_mainloop;
pthread_t tid_csqloop;
pthread_t tid_atloop;
//static pthread_mutex_t em350_mutex_lock;
int ATFlag = 0;

static int cmd_system(char* file_name, char* resp){

	FILE* tmp_fd ;
	char cmd_buffer[190] ;
	char read_buffer[256] ;
	int ret ;

	sprintf(cmd_buffer, "busybox echo -e '%s\r\n' | busybox microcom -t 1000 -s 115200 /dev/ttyUSB2", file_name) ;
	
	//sprintf(cmd_buffer, "busybox microcom -t 1000 -s 115200 /dev/ttyUSB2 < %s", file_name) ;
	//command_mutex_lock() ;
	
	log_out("cmd_system() debug001...\n") ;
    tmp_fd = popen(cmd_buffer, "r") ;
	if(NULL==tmp_fd){
		goto error_001 ;
	}

	log_out("cmd_system() debug002...\n") ;

	memset(read_buffer, 0, sizeof(read_buffer)) ;

	ret = fread(read_buffer, sizeof(char), sizeof(read_buffer)-1, tmp_fd) ;

	log_out("cmd_system() debug003...\n") ;

	sprintf(resp, "%s", read_buffer) ;

	log_out("cmd_system() debug004...\n") ;

	log_out(resp) ;

	pclose(tmp_fd) ;

	//command_mutex_unlock() ;

	printf("Debug:Tag for info mutex......\n") ;

	return ret ;

error_001:
	return -1 ;
}



int csq_command( /*int type,*/ char* param_string, char* out_string){

	int ret ;
	int i ;
	char command[128] ;
	char response[260] ;
	char* sub_begin 	= NULL ;
	char* sub_end 		= NULL ;
	int sub_len 		= 0 ;
	char* tag_begin 	= NULL ;
	ret 				= 0 ;

    memset(response, 0, sizeof(response)) ;

	if(out_string==NULL){
		printf("Error:For GET_CSQ, out_string is NULL\n") ;
		goto error_001 ;
	}

	sprintf(command, "AT+CSQ") ;
	ret = cmd_system(command, response) ;
	if(ret<0){
		goto error_002 ;
	}

	/*********************************************
	for(i=0; i<ret; i++ ){
			printf("[%d]%c\n", i, response[i]) ;
	}
	**********************************************/

	tag_begin = strstr(response, "+CSQ:") ;

	if( NULL==tag_begin ){
		goto error_003 ;
	}


        sub_end = strchr(tag_begin, ',') ;
        sub_begin = strchr(tag_begin, ':') ;

        if( !sub_begin || !sub_end || (sub_begin+4)<sub_end){
                printf("Error:response from em350(CSQ) error!\n") ;
                goto error_004 ;
        }

        sub_begin = sub_begin + 2 ;
        sub_len = sub_end - sub_begin ;

        strncpy(out_string, sub_begin, sub_len) ;

	return 0 ;

error_004:

error_003:

error_002:

error_001:
	return -1 ;
}
//pthread_t tid_socketread;
//static int clnt_sock;
//static char buf[256];
//static char dest[256];


static int at_command(char* dest , char* command)
{
    FILE* tmp_fd;
    char readbuf[128];
    char cmdbuf[256];
    int ret;
    char* sub_begin = NULL;
    char* sub_end = NULL;
    char* tag_begin = NULL;
    int str_len;
    
    
    /*管道指令通信 */
    sprintf(cmdbuf , "busybox echo -e '%s\r\n' | busybox microcom -t 1000 -s 115200 /dev/ttyUSB2", command); 
    tmp_fd = popen(cmdbuf , "r");
	//printf("%s\n" , cmdbuf);

    if(tmp_fd == NULL)
        printf("popen error!\r\n");

    memset(readbuf , 0 ,sizeof(readbuf));

    ret = fread(readbuf , sizeof(char) , sizeof(readbuf), tmp_fd);
    if(ret <= 0){
        printf("read data failed!\r\n");
        return -1;
    }
	pclose(tmp_fd);
	// printf("======================================\n");
	// printf("%s\n" , readbuf);
	// printf("======================================\n");
    tag_begin = strstr(readbuf , "SSIM:");
    if(!tag_begin){
        if(!strstr(readbuf , "ERROR")){
            if(!strstr(readbuf , "OK")){
				strncpy(dest , "ERROR" , 6);
                return -2;
            }else{
				strncpy(dest , "OK" , 3);
                return 0;
            }
        }else{
			strncpy(dest , "ERROR" , 6);
            return -2;
        }
    }else{
        sub_begin = strchr(tag_begin , ':');
        if(sub_begin == NULL){
            return -2;
        }
        sub_end = strstr(tag_begin , "OK");
        if(sub_end == NULL){
            return -2;
        }
        str_len = sub_end - sub_begin;
        sub_begin = sub_begin + 1;
        strncpy(dest , sub_begin , str_len-1);
        return 0;
    }
    
}

static void* main_loop(void* param)
{
	char csq_string[8] ;
	char debug_msg[32] ;

	int current_csq  ;
	int ret;
	RLOGD("songweishuai main_loop ATFlag begin\n");

	while(1){
		sleep(2);
		RLOGD("songweishuai main_loop ATFlag:%d\n",ATFlag);
		if(ATFlag == 0)
		{
			memset(csq_string, 0, sizeof(csq_string)) ;

			log_out("debug AAA ...\n") ;

            ret = csq_command(/*GET_CSQ,*/ NULL, csq_string) ;
			
			if( 0!=ret ){
				RLOGD("songweishuai main_loop csq_command ret:%d\n",ret);
				sleep(2) ;
				continue ;
			}

			log_out("debug BBB ...\n") ;

            current_csq = atoi(csq_string) ;

			log_out("debug 001 ...\n") ;
			sprintf(debug_msg, "GET-CSQ:%s\n", csq_string) ;
			log_out(debug_msg) ;
			log_out("debug 002 ...\n") ;
			
			RLOGD("songweishuai main_loop csq_command current_csq:%d,csq:%d\n",current_csq,csq);

			if( current_csq != csq )
			{
				//log_out("debug 003 ...\n") ;

				RIL_SignalStrength_v6 signalStrength;

				memset(&signalStrength, 0, sizeof(RIL_SignalStrength_v6));

				//#if ((PLATFORM_VERSION >= 420) || ((PLATFORM_VERSION < 100) && (PLATFORM_VERSION >= 42)))
#if (RIL_VERSION >= 7)
				signalStrength.LTE_SignalStrength.signalStrength = 99;
				signalStrength.LTE_SignalStrength.rsrp = 0x7FFFFFFF;
				signalStrength.LTE_SignalStrength.rsrq = 0x7FFFFFFF;
				signalStrength.LTE_SignalStrength.rssnr = 0x7FFFFFFF;
				signalStrength.LTE_SignalStrength.cqi = 0x7FFFFFFF;
#else
				signalStrength.LTE_SignalStrength.signalStrength = -1;
				signalStrength.LTE_SignalStrength.rsrp = -1;
				signalStrength.LTE_SignalStrength.rsrq = -1;
				signalStrength.LTE_SignalStrength.rssnr = -1;
				sig			RIL_onUnsolicitedResponse(RIL_UNSOL_SIGNAL_STRENGTH, &signalStrength, sizeof(RIL_SignalStrength_v6)) ;
				csq = current_csq ;nalStrength.LTE_SignalStrength.cqi = -1;
#endif
				//signalStrength.GW_SignalStrength.signalStrength = 28;
				signalStrength.GW_SignalStrength.signalStrength = current_csq ;
				signalStrength.GW_SignalStrength.bitErrorRate = 99;

				RIL_onUnsolicitedResponse(RIL_UNSOL_SIGNAL_STRENGTH, &signalStrength, sizeof(RIL_SignalStrength_v6)) ;
				csq = current_csq ;
			}

		RLOGD("songweishuai main_loop end\n");
		
		sleep(2);


		/*
		log_out("before RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED\n") ;
		RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED, NULL, 0) ;
		log_out("unsolicitedResponse(RIL_UNSOL_RESPONSE_VOICE_NETWORK_STATE_CHANGED, NULL, 0)\n") ;
		sleep(3) ;
			

		log_out("before RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED\n") ;
		RIL_onUnsolicitedResponse(RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED, NULL, 0) ;
		log_out("unsolicitedResponse(RIL_UNSOL_RESPONSE_RADIO_STATE_CHANGED, NULL, 0)\n") ;
		sleep(2);
		*/
		}
		
	}
	return NULL;
		
}

static void* at_loop(void *param){

	int ret ;
	const char* str = "abc";
    const char final[] = "AT^SSIM=";
    char check[] = "AT^SSIM?";
	char* first = NULL;
	char strbind[128];
	char sim_en[] = "AT^SSWEN=1";
	const char req_yes[] = "1\n";
	const char req_no[] = "0\n";
	const char cmp[] = "1,";
	char buffer[128];
    char dest[256];
	int socket_fd;
	socklen_t lens;
	fd_set rfds; 
    struct timeval tv; 
    int retval,maxfd; 
	printf("this is a test msg!\n");
    socket_fd = socket(AF_INET , SOCK_STREAM , 0);
	log_out("debug 004 ...\n") ;
	
	if(socket_fd < 0){
		perror("creat socket_fd error:");
	}else{
		printf("successful\n");
	}

    struct sockaddr_in serv_addr , c_addr;
	
    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(9900);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

    if(bind(socket_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){
		printf("bind socket error!\n");
	}
    log_out("debug 006 ...\n") ;
	
    
	listen(socket_fd, 20);
	log_out("debug 007 ...\n") ;
	
    while(1)
    {
		RLOGD("songweishuai wait connect ATFlag is :%d\n" , ATFlag);
		//pthread_mutex_unlock(&em350_mutex_lock);
        int clnt_sock = accept(socket_fd , (struct  sockaddr*)&c_addr , &lens);
        if(clnt_sock < 0){
            RLOGD(" songweishuai socket connect failed!\r\n");
			perror("accept");
        }
		RLOGD(" songweishuai already connected------------------------\n");
		while (1)
		{
			//pthread_mutex_lock(&em350_mutex_lock);
			ATFlag = 1;
			FD_ZERO(&rfds); 
            FD_SET(0, &rfds); 
            maxfd = 0; 
            FD_SET(clnt_sock, &rfds); 

			if(maxfd < clnt_sock) 
                maxfd = clnt_sock; 

			tv.tv_sec = 6; 
            tv.tv_usec = 0; 

			retval = select(maxfd+1, &rfds, NULL, NULL, &tv); 
            if(retval <= 0)
			{ 
                RLOGD("songweishuai select出错，与该客户端连接的程序将退出\n"); 
				ATFlag = 0;
                break; 
            }
			else
			{
				if(FD_ISSET(clnt_sock, &rfds))
				{
					memset(buffer , 0 , sizeof(buffer));

					ret = recv(clnt_sock , buffer , sizeof(buffer) , 0);
					if(ret <= 0){
						RLOGD("songweishuai read buffer failed!\r\n");
						close(clnt_sock);
						ATFlag = 0;
						break;
        			}
					RLOGD("songweishuai recv data is:%s\n",buffer);

					if(strncmp(buffer , str , 3) == 0)
					{
						memset(dest , 0 , sizeof(dest));
						ret = at_command(dest , check);
						printf("the first answer is : %s\n" , dest);
						
						ret = send(clnt_sock , dest , strlen(dest) , 0);

						RLOGD("songweishuai the first send ret is :%d\n" , ret);

						//pthread_mutex_unlock(&em350_mutex_lock);
						ATFlag = 0;
						close(clnt_sock);
	
					}

					if(strncmp(buffer , cmp , 2) == 0)
					{
						memset(strbind , 0 , sizeof(strbind));
						strcat(strbind , final);
						strcat(strbind , buffer+2);

						RLOGD("songweishuai the strbind is : %s\n" , strbind);

						memset(dest , 0 , sizeof(dest));
						ret = at_command(dest , sim_en);

						RLOGD("songweishuai the second no.1 answer is : %s , ret = %d\n" , dest , ret);
						
						usleep(10*1000);
						memset(dest , 0 , sizeof(dest));   
						ret = at_command(dest , strbind);

						RLOGD("songweishuai the second no.2 answer is : %s , ret = %d\n" , dest , ret);

						if(ret < 0)
						{
							ret = send(clnt_sock , req_no , strlen(req_no) , 0);
							RLOGD("songweishuai the second222 send ret is :%d\n" , ret);
							//pthread_mutex_unlock(&em350_mutex_lock);
							ATFlag = 0;
							close(clnt_sock);	
						}
						else
						{	
							ret = send(clnt_sock , req_yes , strlen(req_yes) , 0);
							RLOGD("songweishuai the second send ret is :%d\n" , ret);
							//pthread_mutex_unlock(&em350_mutex_lock);
							ATFlag = 0;
							close(clnt_sock);
						}
					}
				}
			}
			ATFlag = 0;
    	}
	}
	// printf("----------------------------");
	// pthread_mutex_unlock(&em350_mutex_lock);	

/*****************************************************************************
	while(1){

reopen:
		if(s_fd<0){

			s_fd = open(TTY_USB0, O_RDWR) ;
			if(s_fd<0){

				sleep(3) ;
				goto reopen ;

			}

		}

		ret = pthread_create(&read_thread_id, NULL, read_thread, NULL) ;
		if(ret<0){

			printf("Error:call pthread_create() fail!\n") ;
			goto reopen ;
		}

		pthread_mutex_lock(&read_thread_mtx) ;
		pthread_cond_wait(&read_thread_cond, &read_thread_mtx);
		pthread_mutex_unlock(&read_thread_mtx) ;

	}

*********************************************************************************/

	return NULL ;

}




const RIL_RadioFunctions *RIL_Init(const struct RIL_Env *env, int argc, char **argv)
{
	int ret;
	int fd = -1;
	int opt;

	pthread_attr_t attr;
	pthread_attr_t attr1;

	ret = log_init() ;
	if(0==ret){

		log_out("log init success\n") ;
	}

	///***********************************************************
	//pthread_mutex_init (&em350_mutex_lock, NULL);

	pthread_attr_init (&attr);
	pthread_attr_init (&attr1);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setdetachstate(&attr1, PTHREAD_CREATE_DETACHED);

	ret = pthread_create(&tid_mainloop, &attr, main_loop, NULL);
	if(ret<0){

		log_out("thread-mainLoop created fail!\n");
	}else{
		log_out("thread-mainLoop created success\n");
	}

	ret = pthread_create(&tid_atloop, &attr1, at_loop, NULL);
	if(ret<0){

		log_out("thread-atloop created fail!\n");
	}else{
		log_out("thread-atloop created success\n");
	}
	//*************************************************************/
	// while(1){
	// 	sleep(1);
	// }
	

	return &s_callbacks;
}

