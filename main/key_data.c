#include "key_data.h"
#include "spi_flash_mmap.h"
#include "esp_partition.h"
#include "esp32s3/rom/rtc.h"
#include "esp32s3/rom/spi_flash.h"
#include "esp_log.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#define KEY_DATA_TAG "KEY_DATA"
/*
  *The size of a single write and read cannot exceed one sector.
*/
static esp_err_t key_data_flash_read(void * buffer, uint32_t offset, uint32_t length)
{
    esp_err_t err;
    if(buffer ==NULL || (length > KEY_DATA_SECTOR_SIZE))
    {
        ESP_LOGE(KEY_DATA_TAG, "ESP_ERR_INVALID_ARG");
        return ESP_ERR_INVALID_ARG;
    }

    const esp_partition_t *key_data_partition = esp_partition_find_first(0x40,0x00,"key_data");
    if(key_data_partition == NULL)
    {
        ESP_LOGE(KEY_DATA_TAG, "Flash partition not found.");
        return ESP_FAIL;
    }
    // ESP_LOGE(KEY_DATA_TAG, "key_data_partition %d",key_data_partition->size);
    err = esp_partition_read(key_data_partition, offset, buffer,length);
    if(err != ESP_OK)
    {
        ESP_LOGE(KEY_DATA_TAG, "Flash read failed.");
        return err;
    }
    return err;
}

static esp_err_t key_data_flash_write(void * buffer, uint32_t offset, uint32_t length)
{
    esp_err_t err;
    if(buffer ==NULL || (length > KEY_DATA_SECTOR_SIZE))
    {
        ESP_LOGE(KEY_DATA_TAG, "ESP_ERR_INVALID_ARG");
        return ESP_ERR_INVALID_ARG;
    }
    const esp_partition_t *key_data_partition = esp_partition_find_first(0x40,0x00,"key_data");
    if(key_data_partition == NULL)
    {
        ESP_LOGE(KEY_DATA_TAG, "Flash partition not found.");
        return ESP_FAIL;
    }

    err = esp_partition_erase_range(key_data_partition, offset, KEY_DATA_SECTOR_SIZE);
    if(err != ESP_OK)
    {
        ESP_LOGE(KEY_DATA_TAG, "Flash erase failed.");
        return err;
    }
    
    err = esp_partition_write(key_data_partition, offset, buffer, length);
    if(err != ESP_OK)
    {
        ESP_LOGE(KEY_DATA_TAG, "Flash write failed.");
        return err;
    }
    return err;
}

void key_set_app0_info(void * app0_info,uint16_t app0_info_len)
{
    esp_err_t err; 
    err = key_data_flash_write(app0_info,KEY_APP0_INFO_ADDRESS,app0_info_len);
    if(err != ESP_OK)
    {
        ESP_LOGE(KEY_DATA_TAG, "key_set_ble_mac failed.");
    }
}

void key_get_app0_info(void * app0_info,uint16_t app0_info_len)
{
    esp_err_t err; 
    err = key_data_flash_read(app0_info,KEY_APP0_INFO_ADDRESS,app0_info_len);
    if(err != ESP_OK)
    {
        ESP_LOGE(KEY_DATA_TAG, "key_get_ble_mac failed.");
    }
}



void key_set_app1_info(void * app1_info,uint16_t app1_info_len)
{
    esp_err_t err; 
    err = key_data_flash_write(app1_info,KEY_APP1_INFO_ADDRESS,app1_info_len);
    if(err != ESP_OK)
    {
        ESP_LOGE(KEY_DATA_TAG, "key_set_app1_info failed.");
    }
}

void key_get_app1_info(void * app1_info,uint16_t app1_info_len)
{
    esp_err_t err; 
    err = key_data_flash_read(app1_info,KEY_APP1_INFO_ADDRESS,app1_info_len);
    if(err != ESP_OK)
    {
        ESP_LOGE(KEY_DATA_TAG, "key_get_app1_info failed.");
    }
}
