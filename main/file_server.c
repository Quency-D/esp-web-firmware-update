#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#include "esp_err.h"
#include "esp_log.h"

#include "esp_vfs.h"
#include "esp_spiffs.h"
#include "esp_http_server.h"

#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "esp_http_client.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"
#include "key_data.h"

#include "errno.h"

/* Max length a file path can have on storage */
#define FILE_PATH_MAX (64)

/* Max size of an individual file. Make sure this
 * value is same as that set in upload_script.html */
#define MAX_FILE_SIZE   (2048*1024) // 200 KB
#define MAX_FILE_SIZE_STR "2M"

/* Scratch buffer size */
#define SCRATCH_BUFSIZE  8192

struct file_server_data {
    /* Base path of file storage */
    char base_path[ESP_VFS_PATH_MAX + 1];

    /* Scratch buffer for temporary storage during file transfer */
    char scratch[SCRATCH_BUFSIZE];
};
#define PARTITION_NAME_LEN (4+1) // 算上结束符
#define APP0_PARTITION_NAME "app0"
#define APP1_PARTITION_NAME "app1"

firmware_info_t app1_info,app0_info;

static const char *TAG = "firmware_server";

/* Handler to redirect incoming GET request for /index.html to /
 * This can be overridden by uploading file with same name */
static esp_err_t index_html_get_handler(httpd_req_t *req)
{
    httpd_resp_set_status(req, "307 Temporary Redirect");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);  // Response body can be empty
    return ESP_OK;
}

/* Handler to respond with an icon file embedded in flash.
 * Browsers expect to GET website icon at URI /favicon.ico.
 * This can be overridden by uploading file with same name */
static esp_err_t favicon_get_handler(httpd_req_t *req)
{
    extern const unsigned char favicon_ico_start[] asm("_binary_favicon_ico_start");
    extern const unsigned char favicon_ico_end[]   asm("_binary_favicon_ico_end");
    const size_t favicon_ico_size = (favicon_ico_end - favicon_ico_start);
    httpd_resp_set_type(req, "image/x-icon");
    httpd_resp_send(req, (const char *)favicon_ico_start, favicon_ico_size);
    return ESP_OK;
}

/* Send HTTP response with a run-time generated html consisting of
 * a list of all files and folders under the requested path.
 * In case of SPIFFS this returns empty list when path is any
 * string other than '/', since SPIFFS doesn't support directories */
static esp_err_t http_resp_dir_html(httpd_req_t *req, const char *dirpath)
{
    /* Get handle to embedded file upload script */
    extern const unsigned char upload_script_start[] asm("_binary_firmware_update_html_start");
    extern const unsigned char upload_script_end[]   asm("_binary_firmware_update_html_end");
    const size_t upload_script_size = (upload_script_end - upload_script_start);

    /* Add file upload form and script which on execution sends a POST request to /upload */
    httpd_resp_send_chunk(req, (const char *)upload_script_start, upload_script_size);

    if(app0_info.firmware_valid_flag == FIRMWARE_VALID)
    {
        httpd_resp_sendstr_chunk(req, "<tr><td>app0</td><td>2097152 bytes</td><td>");
        httpd_resp_sendstr_chunk(req, app0_info.firmware_name);
        httpd_resp_sendstr_chunk(req, "</td><td>");
        httpd_resp_sendstr_chunk(req, app0_info.firmware_size);
        httpd_resp_sendstr_chunk(req, " bytes</td><td>");
        httpd_resp_sendstr_chunk(req, app0_info.firmware_upload_time);
        httpd_resp_sendstr_chunk(req, "</td><td><form method=\"post\" action=\"/run/app0\"><button type=\"submit\">Run</button></form></td><td><form method=\"post\" action=\"/erase/app0\"><button type=\"submit\">Erase</button></form></td></tr>");
    }

    if(app1_info.firmware_valid_flag == FIRMWARE_VALID)
    {
        httpd_resp_sendstr_chunk(req, "<tr><td>app1</td><td>2097152 bytes</td><td>");
        httpd_resp_sendstr_chunk(req, app1_info.firmware_name);
        httpd_resp_sendstr_chunk(req, "</td><td>");
        httpd_resp_sendstr_chunk(req, app1_info.firmware_size);
        httpd_resp_sendstr_chunk(req, " bytes</td><td>");
        httpd_resp_sendstr_chunk(req, app1_info.firmware_upload_time);

        httpd_resp_sendstr_chunk(req, "</td><td><form method=\"post\" action=\"/run/app1\"><button type=\"submit\">Run</button></form></td><td><form method=\"post\" action=\"/erase/app1\"><button type=\"submit\">Erase</button></form></td></tr>");
    }
    /* Finish the file list table */
    httpd_resp_sendstr_chunk(req, "</tbody></table>");

    /* Send remaining chunk of HTML file to complete it */
    httpd_resp_sendstr_chunk(req, "</body></html>");

    /* Send empty chunk to signal HTTP response completion */
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}


/* Copies the full path into destination buffer and returns
 * pointer to path (skipping the preceding base path) */
static const char* get_path_from_uri(char *dest, const char *base_path, const char *uri, size_t destsize)
{
    const size_t base_pathlen = strlen(base_path);
    size_t pathlen = strlen(uri);

    const char *quest = strchr(uri, '?');
    if (quest) {
        pathlen = MIN(pathlen, quest - uri);
    }
    const char *hash = strchr(uri, '#');
    if (hash) {
        pathlen = MIN(pathlen, hash - uri);
    }

    if (base_pathlen + pathlen + 1 > destsize) {
        /* Full path string won't fit into destination buffer */
        return NULL;
    }

    /* Construct full path (base + path) */
    strcpy(dest, base_path);
    strlcpy(dest + base_pathlen, uri, pathlen + 1);

    printf(" %s  \r\n", dest + base_pathlen);

    /* Return pointer to path, skipping the base */
    return dest + base_pathlen;
}

/* Handler to download a file kept on the server */
static esp_err_t index_loading_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];

    const char *filename = get_path_from_uri(filepath, ((struct file_server_data *)req->user_ctx)->base_path,
                                             req->uri, sizeof(filepath));
    if (!filename) 
    {
        ESP_LOGE(TAG, "Filename is too long");
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename too long");
        return ESP_FAIL;
    }

    /* If name has trailing '/', respond with directory contents */
    if (filename[strlen(filename) - 1] == '/') 
    {
        return http_resp_dir_html(req, filepath);
    }
    
    /* If file not present on SPIFFS check if URI
        * corresponds to one of the hardcoded paths */
    if (strcmp(filename, "/index.html") == 0) 
    {
        return index_html_get_handler(req);
    } 
    else if (strcmp(filename, "/favicon.ico") == 0) 
    {
        return favicon_get_handler(req);
    }
  
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "address not found");
    return ESP_FAIL;

    /* Respond with an empty chunk to signal HTTP response completion */
#ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
    httpd_resp_set_hdr(req, "Connection", "close");
#endif
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* Handler to upload a file onto the server */
static esp_err_t upload_post_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];
    char partition_name[PARTITION_NAME_LEN];
    firmware_info_t *app_info;

    /* Skip leading "/upload" from URI to get filename */
    /* Note sizeof() counts NULL termination hence the -1 */
    const char *filename = get_path_from_uri(filepath, ((struct file_server_data *)req->user_ctx)->base_path,
                                             req->uri + sizeof("/upload") - 1, sizeof(filepath));
    if (!filename) 
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename too long");
        return ESP_FAIL;
    }

    /* Filename cannot have a trailing '/' */
    if (filename[strlen(filename) - 1] == '/') 
    {
        ESP_LOGE(TAG, "Invalid filename : %s", filename);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Invalid filename");
        return ESP_FAIL;
    }

    memcpy(partition_name,filename+1,PARTITION_NAME_LEN-1);
    partition_name[PARTITION_NAME_LEN-1] =  '\0';

    esp_err_t err;
    /* update handle : set by esp_ota_begin(), must be freed via esp_ota_end() */
    esp_ota_handle_t update_handle = 0;
    const esp_partition_t *update_partition = NULL;

    if((strncmp(APP0_PARTITION_NAME,partition_name,strlen(APP0_PARTITION_NAME))==0))
    {
        /*
          *This is a reverse selection.
        */
        app_info = &app0_info;
        const esp_partition_t *app1_partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_OTA_1,"app1");
        update_partition = esp_ota_get_next_update_partition(app1_partition);
        app_info->firmware_valid_flag = FIRMWARE_INVALID;
        key_set_app0_info(app_info,sizeof(firmware_info_t));
    }
    else if(strncmp(APP1_PARTITION_NAME,partition_name,strlen(APP1_PARTITION_NAME))==0)
    {
        app_info = &app1_info;
        const esp_partition_t *app0_partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_OTA_0,"app0");
        update_partition = esp_ota_get_next_update_partition(app0_partition);
        app_info->firmware_valid_flag = FIRMWARE_INVALID;
        key_set_app1_info(app_info,sizeof(firmware_info_t));
    }
    else
    {
        ESP_LOGE(TAG, "Invalid partition name: %s", partition_name);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid partition name");
        return ESP_FAIL;
    }
    if(update_partition == NULL)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,"Partition lookup failed.");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%"PRIx32,
             update_partition->subtype, update_partition->address);

    err = esp_partition_erase_range(update_partition, 0, update_partition->erase_size);
    if(err != ESP_OK)
    {
        ESP_LOGE(TAG, "Flash erase failed.");
        return err;
    }
    err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle);
    if (err != ESP_OK) 
    {
        ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
        esp_ota_abort(update_handle);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_begin failed");
        return ESP_FAIL;
    }

    /* File cannot be larger than a limit */
    if (req->content_len > MAX_FILE_SIZE) 
    {
        ESP_LOGE(TAG, "Firmware too large : %d bytes", req->content_len);
        /* Respond with 400 Bad Request */
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Firmware size must be less than "
                            MAX_FILE_SIZE_STR "!");
        /* Return failure to close underlying connection else the
         * incoming file content will keep the socket busy */
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Receiving firmware : %s...", filename);

    /* Retrieve the pointer to scratch buffer for temporary storage */
    char *buf = ((struct file_server_data *)req->user_ctx)->scratch;
    int received;

    /* Content length of the request gives
     * the size of the file being uploaded */
    int remaining = req->content_len;

    while (remaining > 0)
    {
        ESP_LOGI(TAG, "Remaining size : %d", remaining);
        /* Receive the file part by part into a buffer */
        if ((received = httpd_req_recv(req, buf, MIN(remaining, SCRATCH_BUFSIZE))) <= 0) 
        {
            if (received == HTTPD_SOCK_ERR_TIMEOUT) 
            {
                /* Retry if timeout occurred */
                continue;
            }
            esp_ota_abort(update_handle);
            ESP_LOGE(TAG, "firmware reception failed!");
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to receive firmware");
            return ESP_FAIL;
        }
#if 1
        if (( remaining == req->content_len) && received > sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t))
        {
            esp_app_desc_t new_app_info;
            memcpy(&new_app_info, &buf[sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)], sizeof(esp_app_desc_t));
            ESP_LOGE(TAG, "New firmware version: %s", new_app_info.version);
            ESP_LOGE(TAG, "project_name: %s", new_app_info.project_name);
            ESP_LOGE(TAG, "time: %s data: %s", new_app_info.time,new_app_info.date);
            ESP_LOGE(TAG, "idf_ver: %s ", new_app_info.idf_ver);
            for(int i=0; i< 32;i++)
            {
                printf("%02x",new_app_info.app_elf_sha256[i]);
            }
            printf("hello world\r\n");
        }
#endif
        err = esp_ota_write( update_handle, (const void *)buf, received);
        if (err != ESP_OK)
        {
            esp_ota_abort(update_handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_write failed");
            return ESP_FAIL;
        }
        remaining -= received;
    }

    err = esp_ota_end(update_handle);
    if (err != ESP_OK) 
    {
        if (err == ESP_ERR_OTA_VALIDATE_FAILED)
        {
            ESP_LOGE(TAG, "Image validation failed, image is corrupted");
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Image validation failed, image is corrupted");
        } else
        {
            ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        }
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_end faile");
        return ESP_FAIL;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) 
    {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_set_boot_partition failed ");
        return ESP_FAIL;
    }
    int time_index=0,name_index=0;
    for(int i =1,flag_num=0;filename[i]!='\0';i++)
    {
        if((filename[i] == '_') && (flag_num <= 1))
        {
            flag_num +=1;
        }
        else if(flag_num == 1)
        {
            if(filename[i] == '.')
            {
                app_info->firmware_upload_time[time_index++] = ' ';
            }
            else
            {
                app_info->firmware_upload_time[time_index++] = filename[i];
            }
        }
        else if(flag_num >  1)
        {
            app_info->firmware_name[name_index++] = filename[i];
        }
    }
    app_info->firmware_upload_time[time_index++] = '\0';
    app_info->firmware_name[name_index++]   = '\0';
    app_info->firmware_valid_flag = FIRMWARE_VALID;
    sprintf(app_info->firmware_size,"%d",req->content_len);

#if 0
    printf("%s\r\n",app_info->firmware_upload_time);
    printf("%s\r\n",app_info->firmware_name);
    printf("%s\r\n",app_info->firmware_size);
    printf("%s\r\n",partition_name);
#endif

    if((strncmp(APP0_PARTITION_NAME,partition_name,strlen(APP0_PARTITION_NAME))==0))
    {
        key_set_app0_info(app_info,sizeof(firmware_info_t));
    }
    else if(strncmp(APP1_PARTITION_NAME,partition_name,strlen(APP1_PARTITION_NAME))==0)
    {
        key_set_app1_info(app_info,sizeof(firmware_info_t));
    }

    /* Close file upon upload completion */
    ESP_LOGI(TAG, "firmware reception complete");
    /* Redirect onto root to see the updated file list */
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
#ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
    httpd_resp_set_hdr(req, "Connection", "close");
#endif
    httpd_resp_sendstr(req, "File uploaded successfully");
    return ESP_OK;
}

static esp_err_t run_post_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];
    char partition_name[PARTITION_NAME_LEN];
    firmware_info_t *run_app_info;
    /* Skip leading "/delete" from URI to get filename */
    /* Note sizeof() counts NULL termination hence the -1 */
    const char *filename = get_path_from_uri(filepath, ((struct file_server_data *)req->user_ctx)->base_path,
                                             req->uri  + sizeof("/run") - 1, sizeof(filepath));
    if (!filename)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename too long");
        return ESP_FAIL;
    }

    /* Filename cannot have a trailing '/' */
    if (filename[strlen(filename) - 1] == '/')
    {
        ESP_LOGE(TAG, "Invalid filename : %s", filename);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Invalid filename");
        return ESP_FAIL;
    }

    memcpy(partition_name,filename+1,PARTITION_NAME_LEN-1);
    partition_name[PARTITION_NAME_LEN-1] =  '\0';
    
    if((strncmp(APP0_PARTITION_NAME,partition_name,strlen(APP0_PARTITION_NAME))==0))
    {
        /*
          *This is a reverse selection.
        */
        run_app_info = &app0_info;
        const esp_partition_t *app0_partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_OTA_0,"app0");
        if(run_app_info->firmware_valid_flag == FIRMWARE_VALID)
        {
            esp_err_t err = esp_ota_set_boot_partition(app0_partition);
            if (err != ESP_OK) 
            {
                ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to set running partition.");
                return ESP_FAIL;
            }
        }
        else
        {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "There is no firmware in this partition.");
            return ESP_FAIL;
        }
    }
    else if(strncmp(APP1_PARTITION_NAME,partition_name,strlen(APP1_PARTITION_NAME))==0)
    {
        run_app_info = &app1_info;
        const esp_partition_t *app1_partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_OTA_1,"app1");
        if(run_app_info->firmware_valid_flag == FIRMWARE_VALID)
        {
            esp_err_t err = esp_ota_set_boot_partition(app1_partition);
            if (err != ESP_OK) 
            {
                ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to set running partition.");
                return ESP_FAIL;
            }
        }
        else
        {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "There is no firmware in this partition.");
            return ESP_FAIL;
        }
    }
    else
    {
        ESP_LOGE(TAG, "Invalid partition name: %s", partition_name);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid partition name");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Next Run Partition : %s", partition_name);

    /* Redirect onto root to see the updated file list */
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
#ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
    httpd_resp_set_hdr(req, "Connection", "close");
#endif
    httpd_resp_sendstr(req, "File deleted successfully");
    return ESP_OK;
}


/* Handler to delete a file from the server */
static esp_err_t erase_post_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];
    char partition_name[PARTITION_NAME_LEN];
    firmware_info_t *erase_app_info;
    /* Skip leading "/delete" from URI to get filename */
    /* Note sizeof() counts NULL termination hence the -1 */
    const char *filename = get_path_from_uri(filepath, ((struct file_server_data *)req->user_ctx)->base_path,
                                             req->uri  + sizeof("/erase") - 1, sizeof(filepath));
    if (!filename)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename too long");
        return ESP_FAIL;
    }

    /* Filename cannot have a trailing '/' */
    if (filename[strlen(filename) - 1] == '/')
    {
        ESP_LOGE(TAG, "Invalid filename : %s", filename);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Invalid filename");
        return ESP_FAIL;
    }

    memcpy(partition_name,filename+1,PARTITION_NAME_LEN-1);
    partition_name[PARTITION_NAME_LEN-1] =  '\0';
    
    if((strncmp(APP0_PARTITION_NAME,partition_name,strlen(APP0_PARTITION_NAME))==0))
    {
        erase_app_info = &app0_info;
        const esp_partition_t *app0_partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_OTA_0,"app0");
        if(erase_app_info->firmware_valid_flag == FIRMWARE_VALID)
        {
            esp_err_t err = esp_partition_erase_range(app0_partition, 0, app0_partition->size);
            if (err != ESP_OK) 
            {
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Partition erase failed.");
                return ESP_FAIL;
            }
            erase_app_info->firmware_valid_flag = FIRMWARE_INVALID;
            key_set_app0_info(erase_app_info,sizeof(firmware_info_t));
        }

    }
    else if(strncmp(APP1_PARTITION_NAME,partition_name,strlen(APP1_PARTITION_NAME))==0)
    {
        erase_app_info = &app1_info;
        const esp_partition_t *app1_partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_OTA_1,"app1");
        if(erase_app_info->firmware_valid_flag == FIRMWARE_VALID)
        {
            esp_err_t err = esp_partition_erase_range(app1_partition, 0, app1_partition->size);
            if (err != ESP_OK) 
            {
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Partition erase failed.");
                return ESP_FAIL;
            }
            erase_app_info->firmware_valid_flag = FIRMWARE_INVALID;
            key_set_app1_info(erase_app_info,sizeof(firmware_info_t));
        }
    }
    else
    {
        ESP_LOGE(TAG, "Invalid partition name: %s", partition_name);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid partition name");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "The partition %s has been erased.", partition_name);

    /* Redirect onto root to see the updated file list */
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
#ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
    httpd_resp_set_hdr(req, "Connection", "close");
#endif
    httpd_resp_sendstr(req, "File deleted successfully");
    return ESP_OK;
}

/* Function to start the file server */
esp_err_t example_start_file_server(const char *base_path)
{
    key_get_app0_info((void*)&app0_info,sizeof(firmware_info_t));
    key_get_app1_info((void*)&app1_info,sizeof(firmware_info_t));
    static struct file_server_data *server_data = NULL;

    if (server_data)
    {
        ESP_LOGE(TAG, "File server already started");
        return ESP_ERR_INVALID_STATE;
    }

    /* Allocate memory for server data */
    server_data = calloc(1, sizeof(struct file_server_data));
    if (!server_data) 
    {
        ESP_LOGE(TAG, "Failed to allocate memory for server data");
        return ESP_ERR_NO_MEM;
    }
    strlcpy(server_data->base_path, base_path,
            sizeof(server_data->base_path));

    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
config.stack_size = 10*1024;
    /* Use the URI wildcard matching function in order to
     * allow the same handler to respond to multiple different
     * target URIs which match the wildcard scheme */
    config.uri_match_fn = httpd_uri_match_wildcard;

    ESP_LOGI(TAG, "Starting HTTP Server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start file server!");
        return ESP_FAIL;
    }

    /* URI handler for getting uploaded files */
    httpd_uri_t firmware_index = {
        .uri       = "/*",  // Match all URIs of type /path/to/file
        .method    = HTTP_GET,
        .handler   = index_loading_handler,
        .user_ctx  = server_data    // Pass server data as context
    };
    httpd_register_uri_handler(server, &firmware_index);

    /* URI handler for uploading files to server */
    httpd_uri_t firmware_upload = {
        .uri       = "/upload/*",   // Match all URIs of type /upload/path/to/file
        .method    = HTTP_POST,
        .handler   = upload_post_handler,
        .user_ctx  = server_data    // Pass server data as context
    };
    httpd_register_uri_handler(server, &firmware_upload);

    /* URI handler for deleting files from server */
    httpd_uri_t firmware_erase = {
        .uri       = "/erase/*",   // Match all URIs of type /delete/path/to/file
        .method    = HTTP_POST,
        .handler   = erase_post_handler,
        .user_ctx  = server_data    // Pass server data as context
    };
    httpd_register_uri_handler(server, &firmware_erase);


    /* URI handler for deleting files from server */
    httpd_uri_t firmware_run_select = {
        .uri       = "/run/*",   // Match all URIs of type /delete/path/to/file
        .method    = HTTP_POST,
        .handler   = run_post_handler,
        .user_ctx  = server_data    // Pass server data as context
    };
    httpd_register_uri_handler(server, &firmware_run_select);
    return ESP_OK;
}