// derived from https://github.com/hisptoot/BambuSource2Raw/blob/main/BambuSource2Raw/bambusource2raw.cpp
#define BAMBU_DYNAMIC

#include <stdio.h>
#include "BambuTunnel.h"
#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#include <dlfcn.h>
#endif

#define BAMBUE_START_STREAM_RETRY_COUNT (40)

struct BambuLib lib = {0};
static void* module = NULL;

static void* get_function(const char* name)
{
    void* function = NULL;

    if (!module)
    {
        return function;
    }

#if defined(_MSC_VER) || defined(_WIN32)
    function = (void *)GetProcAddress(module, name);
#else
    function = (void *)dlsym(module, name);
#endif

    if (!function)
    {
        fprintf(stderr, ", can not find function %s", name);
        exit(-1);
    }
    return function;
}

#define GET_FUNC(x) *((void **)&lib.x) = get_function(#x)

void bambu_log(void *ctx, int level, tchar const * msg)
{
    if (level <= 1)
    {
#if defined(_MSC_VER) || defined(_WIN32)
      fwprintf(stderr, L"[%d] %s\n", level, msg);
#else
      fprintf(stderr, "[%d] %s\n", level, msg);
#endif
      lib.Bambu_FreeLogMsg(msg);
    }
}

static void write_start_code()
{
    static unsigned char const start_code[4] = {0x00, 0x00, 0x00, 0x01};
    fwrite(start_code, 1, sizeof(start_code), stdout);
}

static unsigned short read_be16(unsigned char const * ptr)
{
    return (unsigned short)((ptr[0] << 8) | ptr[1]);
}

static unsigned int read_be32(unsigned char const * ptr)
{
    return ((unsigned int)ptr[0] << 24) |
           ((unsigned int)ptr[1] << 16) |
           ((unsigned int)ptr[2] << 8) |
           ((unsigned int)ptr[3]);
}

static void emit_avcc_parameter_sets(struct Bambu_StreamInfo const * info)
{
    if (info == NULL || info->format_buffer == NULL || info->format_size < 7)
    {
        return;
    }

    unsigned char const * config = info->format_buffer;
    if (config[0] != 1)
    {
        return;
    }

    size_t offset = 5;
    int num_sps = config[offset++] & 0x1f;
    for (int i = 0; i < num_sps; i++)
    {
        if (offset + 2 > (size_t)info->format_size)
        {
            return;
        }
        unsigned short sps_size = read_be16(config + offset);
        offset += 2;
        if (offset + sps_size > (size_t)info->format_size)
        {
            return;
        }
        write_start_code();
        fwrite(config + offset, 1, sps_size, stdout);
        offset += sps_size;
    }

    if (offset + 1 > (size_t)info->format_size)
    {
        return;
    }
    int num_pps = config[offset++];
    for (int i = 0; i < num_pps; i++)
    {
        if (offset + 2 > (size_t)info->format_size)
        {
            return;
        }
        unsigned short pps_size = read_be16(config + offset);
        offset += 2;
        if (offset + pps_size > (size_t)info->format_size)
        {
            return;
        }
        write_start_code();
        fwrite(config + offset, 1, pps_size, stdout);
        offset += pps_size;
    }
}

static int emit_avcc_sample_as_annexb(unsigned char const * buffer, int size, int nal_length_size, bool prepend_parameter_sets, struct Bambu_StreamInfo const * info)
{
    if (prepend_parameter_sets)
    {
        emit_avcc_parameter_sets(info);
    }

    size_t offset = 0;
    while (offset + (size_t)nal_length_size <= (size_t)size)
    {
        unsigned int nal_size = 0;
        switch (nal_length_size)
        {
        case 1:
            nal_size = buffer[offset];
            break;
        case 2:
            nal_size = read_be16(buffer + offset);
            break;
        default:
            nal_size = read_be32(buffer + offset);
            break;
        }
        offset += (size_t)nal_length_size;
        if (nal_size == 0 || offset + nal_size > (size_t)size)
        {
            return -1;
        }
        write_start_code();
        fwrite(buffer + offset, 1, nal_size, stdout);
        offset += nal_size;
    }
    return 0;
}

int start_bambu_stream(char *camera_url)
{
    Bambu_Tunnel tunnel = NULL;
    int is_bambu_open = 0;
    int ret = 0;
    int video_track_index = -1;
    int nal_length_size = 4;
    bool parameter_sets_emitted = false;
    struct Bambu_StreamInfo video_stream_info;
    memset(&video_stream_info, 0, sizeof(video_stream_info));

    do {
        fprintf(stderr, "Starting Session\n");

        ret = lib.Bambu_Create(&tunnel, camera_url);
        if (ret != 0)
        {
            fprintf(stderr, "Bambu_Create failed 0x%x\n", ret);
            break;
        }

        lib.Bambu_SetLogger(tunnel, bambu_log, tunnel);

        ret = lib.Bambu_Open(tunnel);
        if (ret != 0)
        {
            fprintf(stderr, "Bambu_Open failed: 0x%x\n", ret);
            break;
        }
        is_bambu_open++;

        size_t i;
        for (i = 0; i < BAMBUE_START_STREAM_RETRY_COUNT; i++)
        {
            ret = lib.Bambu_StartStream(tunnel, true);

            if (ret == 0)
            {
                break;
            }

#if defined(_MSC_VER) || defined(_WIN32)
            Sleep(1000);
#else
            usleep(1000 * 1000);
#endif
        }

        if (ret != 0)
        {
            fprintf(stderr, "Bambu_StartStream failed 0x%x\n", ret);
            break;
        }

        int stream_count = lib.Bambu_GetStreamCount(tunnel);
        for (int index = 0; index < stream_count; index++)
        {
            struct Bambu_StreamInfo info;
            memset(&info, 0, sizeof(info));
            if (lib.Bambu_GetStreamInfo(tunnel, index, &info) != 0)
            {
                continue;
            }
            if (info.type == VIDE)
            {
                video_track_index = index;
                video_stream_info = info;
                if (info.format_buffer != NULL && info.format_size >= 5)
                {
                    nal_length_size = (info.format_buffer[4] & 0x03) + 1;
                }
                break;
            }
        }

        int result = 0;
        while (true) 
        {
            Bambu_Sample sample;
            result = lib.Bambu_ReadSample(tunnel, &sample);

            if (result == Bambu_success) 
            {
                if (video_track_index >= 0 && sample.itrack != video_track_index)
                {
                    continue;
                }
                bool prepend_parameter_sets = !parameter_sets_emitted || (sample.flags & f_sync);
                if (video_stream_info.format_type == video_avc_packet)
                {
                    if (emit_avcc_sample_as_annexb(sample.buffer, sample.size, nal_length_size, prepend_parameter_sets, &video_stream_info) != 0)
                    {
                        fprintf(stderr, "ERROR_INVALID_AVCC_SAMPLE\n");
                        ret = -1;
                        break;
                    }
                }
                else
                {
                    if (prepend_parameter_sets)
                    {
                        emit_avcc_parameter_sets(&video_stream_info);
                    }
                    fwrite(sample.buffer, 1, sample.size, stdout);
                }
                parameter_sets_emitted = true;
                fflush(stdout);
                continue;
            } 
            else if (result == Bambu_would_block)
            {
#if defined(_MSC_VER) || defined(_WIN32)
                Sleep(100);
#else
                usleep(100 * 1000);
#endif
                continue;
            }
            else if (result == Bambu_stream_end)
            {
                fprintf(stderr, "Bambu_stream_end\n");
                result = 0;
            }
            else
            {
                result = -1;
                fprintf(stderr, "ERROR_PIPE\n");
                ret = -1;
            }
            break;
        }
    } while (false);

    if (is_bambu_open)
    {
        lib.Bambu_Close(tunnel);
    }

    if (tunnel != NULL)
    {
        lib.Bambu_Destroy(tunnel);
        tunnel = NULL;
    }

    return ret;
}

int main(int argc, char* argv[]){

    if ( argc != 4 ){
        printf("Usage: %s <libBambuSource.so path> <printer address> <access code>", argv[0]);
        exit(1);
    }

    char* bambuLibPath = argv[1];
    char* printerAddress = argv[2];
    char* accessCode = argv[3];

	fprintf(stderr, "Starting Bambu Camera Tunnel\n");
	fprintf(stderr, "  libBambuSource.so path: %s\n", bambuLibPath);
	fprintf(stderr, "  printAddress: %s\n", printerAddress);
	fprintf(stderr, "  accessCode: [redacted]\n\n");


    char camera_url[256];

    snprintf(camera_url, 256, "bambu:///local/%s.?port=6000&user=bblp&passwd=%s", printerAddress, accessCode);

    module = dlopen(bambuLibPath, RTLD_LAZY);
    if (module == NULL)
    {
        fprintf(stderr, "Failed loading libBambuSource.so at path %s\n", bambuLibPath);
        return -1;
    }
    GET_FUNC(Bambu_Init);
    GET_FUNC(Bambu_Deinit);
    GET_FUNC(Bambu_Create);
    GET_FUNC(Bambu_Destroy);
    GET_FUNC(Bambu_Open);
    GET_FUNC(Bambu_StartStream);
    GET_FUNC(Bambu_SendMessage);
    GET_FUNC(Bambu_ReadSample);
    GET_FUNC(Bambu_Close);
    GET_FUNC(Bambu_SetLogger);
    GET_FUNC(Bambu_FreeLogMsg);
    GET_FUNC(Bambu_GetLastErrorMsg);
    GET_FUNC(Bambu_GetStreamCount);
    GET_FUNC(Bambu_GetDuration);
    GET_FUNC(Bambu_GetStreamInfo);

    start_bambu_stream(camera_url);

    return 0;
}
