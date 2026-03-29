#ifndef PFH_BAMBU_CAMERA_RUNTIME_BRIDGE_H
#define PFH_BAMBU_CAMERA_RUNTIME_BRIDGE_H

#include <stdbool.h>

#ifdef _WIN32
typedef wchar_t tchar;
#else
typedef char tchar;
#endif

typedef void* Bambu_Tunnel;
typedef void (*Logger)(void * context, int level, tchar const* msg);

enum Bambu_StreamType
{
    VIDE,
    AUDI
};

enum Bambu_FormatType
{
    video_avc_packet,
    video_avc_byte_stream,
    audio_raw,
    audio_adts
};

struct Bambu_StreamInfo
{
    enum Bambu_StreamType type;
    int sub_type;
    union {
        struct
        {
            int width;
            int height;
            int frame_rate;
        } video;
        struct
        {
            int sample_rate;
            int channel_count;
            int sample_size;
        } audio;
    } format;
    int format_type;
    int format_size;
    unsigned char const * format_buffer;
};

enum Bambu_SampleFlag
{
    f_sync = 1
};

struct Bambu_Sample
{
    int itrack;
    int size;
    int flags;
    unsigned char const * buffer;
    unsigned long long decode_time;
};

enum Bambu_Error
{
    Bambu_success,
    Bambu_stream_end,
    Bambu_would_block,
    Bambu_buffer_limit
};

typedef int (*PFHBambuCreateFn)(Bambu_Tunnel* tunnel, char const* path);
typedef void (*PFHBambuSetLoggerFn)(Bambu_Tunnel tunnel, Logger logger, void * context);
typedef int (*PFHBambuOpenFn)(Bambu_Tunnel tunnel);
typedef int (*PFHBambuStartStreamFn)(Bambu_Tunnel tunnel, bool video);
typedef int (*PFHBambuStartStreamExFn)(Bambu_Tunnel tunnel, int type);
typedef int (*PFHBambuGetStreamCountFn)(Bambu_Tunnel tunnel);
typedef int (*PFHBambuGetStreamInfoFn)(Bambu_Tunnel tunnel, int index, struct Bambu_StreamInfo* info);
typedef int (*PFHBambuReadSampleFn)(Bambu_Tunnel tunnel, struct Bambu_Sample* sample);
typedef int (*PFHBambuSendMessageFn)(Bambu_Tunnel tunnel, int ctrl, char const* data, int len);
typedef void (*PFHBambuCloseFn)(Bambu_Tunnel tunnel);
typedef void (*PFHBambuDestroyFn)(Bambu_Tunnel tunnel);
typedef void (*PFHBambuFreeLogMsgFn)(tchar const* msg);

typedef struct PFHBambuRuntime {
    void* module;
    Bambu_Tunnel tunnel;
    int video_track_index;
    PFHBambuCreateFn create_fn;
    PFHBambuSetLoggerFn set_logger_fn;
    PFHBambuOpenFn open_fn;
    PFHBambuStartStreamFn start_stream_fn;
    PFHBambuStartStreamExFn start_stream_ex_fn;
    PFHBambuGetStreamCountFn get_stream_count_fn;
    PFHBambuGetStreamInfoFn get_stream_info_fn;
    PFHBambuReadSampleFn read_sample_fn;
    PFHBambuSendMessageFn send_message_fn;
    PFHBambuCloseFn close_fn;
    PFHBambuDestroyFn destroy_fn;
    PFHBambuFreeLogMsgFn free_log_msg_fn;
} PFHBambuRuntime;

enum PFHBambuStatus {
    PFHBambuStatusSuccess = 0,
    PFHBambuStatusWouldBlock = 1,
    PFHBambuStatusStreamEnd = 2
};

int pfh_bambu_runtime_open(const char* library_path, const char* printer_address, const char* access_code, PFHBambuRuntime** out_runtime, char** out_error);
int pfh_bambu_runtime_read_sample(PFHBambuRuntime* runtime, unsigned char** out_data, int* out_size, int* out_status, char** out_error);
int pfh_bambu_control_open(const char* library_path, const char* printer_address, const char* access_code, PFHBambuRuntime** out_runtime, char** out_error);
int pfh_bambu_control_send_message(PFHBambuRuntime* runtime, const unsigned char* data, int size, char** out_error);
int pfh_bambu_control_read_message(PFHBambuRuntime* runtime, unsigned char** out_data, int* out_size, int* out_status, char** out_error);
void pfh_bambu_runtime_close(PFHBambuRuntime* runtime);
void pfh_bambu_runtime_free_bytes(unsigned char* data);
void pfh_bambu_runtime_free_string(char* value);

#endif
