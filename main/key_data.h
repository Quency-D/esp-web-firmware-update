#ifndef __KEY_DATA_H_
#define __KEY_DATA_H_
#include "stdint.h"
 
#define KEY_DATA_SECTOR_SIZE 0X1000 //Sector size 4096/4K
//Each sector can have up to 64 sectors in 4k and 256k space to store data.

// Add a sector size to the previous one each time.
#define KEY_APP0_INFO_ADDRESS        (0x00000000)
#define KEY_APP0_INFO_LEN            (KEY_DATA_SECTOR_SIZE)

#define KEY_APP1_INFO_ADDRESS        (KEY_APP0_INFO_ADDRESS + KEY_APP0_INFO_LEN )
#define KEY_APP1_INFO_LEN            (KEY_DATA_SECTOR_SIZE)

/***************************************************************************************/
#define FIRMWARE_NAME_LEN (64)
#define FIRMWARE_SIZE_LEN (64)
#define FIRMWARE_UPLOAD_TIME_LEN (64)
typedef enum
{
    FIRMWARE_VALID    = 0x32,
    FIRMWARE_INVALID  = 0x64
}firmware_valid_flag_t;

typedef struct 
{
    char firmware_name[FIRMWARE_NAME_LEN];
    char firmware_size[FIRMWARE_SIZE_LEN];
    char firmware_upload_time[FIRMWARE_UPLOAD_TIME_LEN];
    firmware_valid_flag_t firmware_valid_flag; 
}firmware_info_t;


/***************************************************************************************/

void key_set_app0_info(void * app0_info,uint16_t app0_info_len);
void key_get_app0_info(void * app0_info,uint16_t app0_info_len);

void key_set_app1_info(void * app1_info,uint16_t app1_info_len);
void key_get_app1_info(void * app1_info,uint16_t app1_info_len);

#endif