#include "bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif

#define BAMBUE_START_STREAM_RETRY_COUNT (40)
#define PFH_BAMBU_CONTROL_STREAM_TYPE (0x3001)

static char* pfh_strdup(const char* message) {
    if (message == NULL) {
        return NULL;
    }
    size_t length = strlen(message) + 1;
    char* copy = (char*)malloc(length);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, message, length);
    return copy;
}

static void pfh_set_error(char** out_error, const char* message) {
    if (out_error == NULL) {
        return;
    }
    *out_error = pfh_strdup(message);
}

static void* pfh_load_module(const char* library_path) {
#ifdef _WIN32
    return (void*)LoadLibraryA(library_path);
#else
    return dlopen(library_path, RTLD_LAZY);
#endif
}

static void pfh_close_module(void* module) {
    if (module == NULL) {
        return;
    }
#ifdef _WIN32
    FreeLibrary((HMODULE)module);
#else
    dlclose(module);
#endif
}

static void* pfh_get_symbol(void* module, const char* name) {
    if (module == NULL) {
        return NULL;
    }
#ifdef _WIN32
    return (void*)GetProcAddress((HMODULE)module, name);
#else
    return dlsym(module, name);
#endif
}

static int pfh_resolve_functions(PFHBambuRuntime* runtime, char** out_error) {
    runtime->create_fn = (PFHBambuCreateFn)pfh_get_symbol(runtime->module, "Bambu_Create");
    runtime->set_logger_fn = (PFHBambuSetLoggerFn)pfh_get_symbol(runtime->module, "Bambu_SetLogger");
    runtime->open_fn = (PFHBambuOpenFn)pfh_get_symbol(runtime->module, "Bambu_Open");
    runtime->start_stream_fn = (PFHBambuStartStreamFn)pfh_get_symbol(runtime->module, "Bambu_StartStream");
    runtime->start_stream_ex_fn = (PFHBambuStartStreamExFn)pfh_get_symbol(runtime->module, "Bambu_StartStreamEx");
    runtime->get_stream_count_fn = (PFHBambuGetStreamCountFn)pfh_get_symbol(runtime->module, "Bambu_GetStreamCount");
    runtime->get_stream_info_fn = (PFHBambuGetStreamInfoFn)pfh_get_symbol(runtime->module, "Bambu_GetStreamInfo");
    runtime->read_sample_fn = (PFHBambuReadSampleFn)pfh_get_symbol(runtime->module, "Bambu_ReadSample");
    runtime->send_message_fn = (PFHBambuSendMessageFn)pfh_get_symbol(runtime->module, "Bambu_SendMessage");
    runtime->close_fn = (PFHBambuCloseFn)pfh_get_symbol(runtime->module, "Bambu_Close");
    runtime->destroy_fn = (PFHBambuDestroyFn)pfh_get_symbol(runtime->module, "Bambu_Destroy");
    runtime->free_log_msg_fn = (PFHBambuFreeLogMsgFn)pfh_get_symbol(runtime->module, "Bambu_FreeLogMsg");

    if (runtime->create_fn == NULL || runtime->open_fn == NULL || runtime->start_stream_fn == NULL ||
        runtime->get_stream_count_fn == NULL || runtime->get_stream_info_fn == NULL || runtime->read_sample_fn == NULL ||
        runtime->close_fn == NULL || runtime->destroy_fn == NULL) {
        pfh_set_error(out_error, "bambu native runtime is missing required symbols");
        return -1;
    }
    return 0;
}

static void pfh_logger(void* context, int level, tchar const* msg) {
    (void)context;
    (void)level;
    (void)msg;
}

int pfh_bambu_runtime_open(const char* library_path, const char* printer_address, const char* access_code, PFHBambuRuntime** out_runtime, char** out_error) {
    if (out_runtime != NULL) {
        *out_runtime = NULL;
    }
    if (library_path == NULL || printer_address == NULL || access_code == NULL) {
        pfh_set_error(out_error, "bambu native runtime is missing required inputs");
        return -1;
    }

    PFHBambuRuntime* runtime = (PFHBambuRuntime*)calloc(1, sizeof(PFHBambuRuntime));
    if (runtime == NULL) {
        pfh_set_error(out_error, "failed to allocate Bambu runtime");
        return -1;
    }

    runtime->module = pfh_load_module(library_path);
    if (runtime->module == NULL) {
        free(runtime);
        pfh_set_error(out_error, "failed loading Bambu camera plugin library");
        return -1;
    }
    if (pfh_resolve_functions(runtime, out_error) != 0) {
        pfh_close_module(runtime->module);
        free(runtime);
        return -1;
    }

    char camera_url[256];
    snprintf(camera_url, sizeof(camera_url), "bambu:///local/%s.?port=6000&user=bblp&passwd=%s", printer_address, access_code);

    int result = runtime->create_fn(&runtime->tunnel, camera_url);
    if (result != 0 || runtime->tunnel == NULL) {
        pfh_set_error(out_error, "Bambu_Create failed");
        pfh_close_module(runtime->module);
        free(runtime);
        return -1;
    }

    if (runtime->set_logger_fn != NULL) {
        runtime->set_logger_fn(runtime->tunnel, pfh_logger, runtime);
    }

    result = runtime->open_fn(runtime->tunnel);
    if (result != 0) {
        pfh_set_error(out_error, "Bambu_Open failed");
        pfh_bambu_runtime_close(runtime);
        return -1;
    }

    for (size_t attempt = 0; attempt < BAMBUE_START_STREAM_RETRY_COUNT; attempt++) {
        result = runtime->start_stream_fn(runtime->tunnel, true);
        if (result == 0) {
            break;
        }
#ifdef _WIN32
        Sleep(1000);
#else
        usleep(1000 * 1000);
#endif
    }
    if (result != 0) {
        pfh_set_error(out_error, "Bambu_StartStream failed");
        pfh_bambu_runtime_close(runtime);
        return -1;
    }

    runtime->video_track_index = -1;
    int stream_count = runtime->get_stream_count_fn(runtime->tunnel);
    for (int index = 0; index < stream_count; index++) {
        struct Bambu_StreamInfo info;
        memset(&info, 0, sizeof(info));
        if (runtime->get_stream_info_fn(runtime->tunnel, index, &info) != 0) {
            continue;
        }
        if (info.type == VIDE) {
            runtime->video_track_index = index;
            break;
        }
    }

    if (out_runtime != NULL) {
        *out_runtime = runtime;
    }
    return 0;
}

int pfh_bambu_control_open(const char* library_path, const char* printer_address, const char* access_code, PFHBambuRuntime** out_runtime, char** out_error) {
    if (out_runtime != NULL) {
        *out_runtime = NULL;
    }
    if (library_path == NULL || printer_address == NULL || access_code == NULL) {
        pfh_set_error(out_error, "bambu native runtime is missing required inputs");
        return -1;
    }

    PFHBambuRuntime* runtime = (PFHBambuRuntime*)calloc(1, sizeof(PFHBambuRuntime));
    if (runtime == NULL) {
        pfh_set_error(out_error, "failed to allocate Bambu runtime");
        return -1;
    }

    runtime->module = pfh_load_module(library_path);
    if (runtime->module == NULL) {
        free(runtime);
        pfh_set_error(out_error, "failed loading Bambu camera plugin library");
        return -1;
    }
    if (pfh_resolve_functions(runtime, out_error) != 0) {
        pfh_close_module(runtime->module);
        free(runtime);
        return -1;
    }
    if (runtime->send_message_fn == NULL) {
        pfh_close_module(runtime->module);
        free(runtime);
        pfh_set_error(out_error, "bambu native runtime is missing Bambu_SendMessage");
        return -1;
    }

    char control_url[256];
    snprintf(control_url, sizeof(control_url), "bambu:///local/%s.?port=6000&user=bblp&passwd=%s", printer_address, access_code);

    int result = runtime->create_fn(&runtime->tunnel, control_url);
    if (result != 0 || runtime->tunnel == NULL) {
        pfh_set_error(out_error, "Bambu_Create failed");
        pfh_close_module(runtime->module);
        free(runtime);
        return -1;
    }

    if (runtime->set_logger_fn != NULL) {
        runtime->set_logger_fn(runtime->tunnel, pfh_logger, runtime);
    }

    result = runtime->open_fn(runtime->tunnel);
    if (result != 0) {
        pfh_set_error(out_error, "Bambu_Open failed");
        pfh_bambu_runtime_close(runtime);
        return -1;
    }

    for (size_t attempt = 0; attempt < BAMBUE_START_STREAM_RETRY_COUNT; attempt++) {
        if (runtime->start_stream_ex_fn != NULL) {
            result = runtime->start_stream_ex_fn(runtime->tunnel, PFH_BAMBU_CONTROL_STREAM_TYPE);
        } else {
            result = runtime->start_stream_fn(runtime->tunnel, false);
        }
        if (result == 0) {
            break;
        }
        if (result != Bambu_would_block) {
            break;
        }
#ifdef _WIN32
        Sleep(100);
#else
        usleep(1000 * 100);
#endif
    }
    if (result != 0) {
        pfh_set_error(out_error, "Bambu_StartStreamEx failed");
        pfh_bambu_runtime_close(runtime);
        return -1;
    }

    if (out_runtime != NULL) {
        *out_runtime = runtime;
    }
    return 0;
}

int pfh_bambu_runtime_read_sample(PFHBambuRuntime* runtime, unsigned char** out_data, int* out_size, int* out_status, char** out_error) {
    if (out_data != NULL) {
        *out_data = NULL;
    }
    if (out_size != NULL) {
        *out_size = 0;
    }
    if (out_status != NULL) {
        *out_status = PFHBambuStatusSuccess;
    }
    if (runtime == NULL || runtime->read_sample_fn == NULL) {
        pfh_set_error(out_error, "bambu native runtime is not open");
        return -1;
    }

    struct Bambu_Sample sample;
    memset(&sample, 0, sizeof(sample));
    int result = runtime->read_sample_fn(runtime->tunnel, &sample);
    if (result == Bambu_would_block) {
        if (out_status != NULL) {
            *out_status = PFHBambuStatusWouldBlock;
        }
        return 0;
    }
    if (result == Bambu_stream_end) {
        if (out_status != NULL) {
            *out_status = PFHBambuStatusStreamEnd;
        }
        return 0;
    }
    if (result != Bambu_success) {
        pfh_set_error(out_error, "Bambu_ReadSample failed");
        return -1;
    }
    if (runtime->video_track_index >= 0 && sample.itrack != runtime->video_track_index) {
        if (out_status != NULL) {
            *out_status = PFHBambuStatusWouldBlock;
        }
        return 0;
    }
    if (sample.buffer == NULL || sample.size <= 0) {
        if (out_status != NULL) {
            *out_status = PFHBambuStatusWouldBlock;
        }
        return 0;
    }

    unsigned char* copy = (unsigned char*)malloc((size_t)sample.size);
    if (copy == NULL) {
        pfh_set_error(out_error, "failed to allocate Bambu sample buffer");
        return -1;
    }
    memcpy(copy, sample.buffer, (size_t)sample.size);
    if (out_data != NULL) {
        *out_data = copy;
    }
    if (out_size != NULL) {
        *out_size = sample.size;
    }
    return 0;
}

int pfh_bambu_control_send_message(PFHBambuRuntime* runtime, const unsigned char* data, int size, char** out_error) {
    if (runtime == NULL || runtime->send_message_fn == NULL || runtime->tunnel == NULL) {
        pfh_set_error(out_error, "bambu native control session is not open");
        return -1;
    }
    if (data == NULL || size <= 0) {
        pfh_set_error(out_error, "bambu control message is empty");
        return -1;
    }

    int result = Bambu_would_block;
    for (size_t attempt = 0; attempt < BAMBUE_START_STREAM_RETRY_COUNT; attempt++) {
        result = runtime->send_message_fn(runtime->tunnel, PFH_BAMBU_CONTROL_STREAM_TYPE, (const char*)data, size);
        if (result == 0) {
            return 0;
        }
        if (result != Bambu_would_block) {
            break;
        }
#ifdef _WIN32
        Sleep(100);
#else
        usleep(1000 * 100);
#endif
    }

    pfh_set_error(out_error, "Bambu_SendMessage failed");
    return -1;
}

int pfh_bambu_control_read_message(PFHBambuRuntime* runtime, unsigned char** out_data, int* out_size, int* out_status, char** out_error) {
    if (out_data != NULL) {
        *out_data = NULL;
    }
    if (out_size != NULL) {
        *out_size = 0;
    }
    if (out_status != NULL) {
        *out_status = PFHBambuStatusSuccess;
    }
    if (runtime == NULL || runtime->read_sample_fn == NULL) {
        pfh_set_error(out_error, "bambu native control session is not open");
        return -1;
    }

    struct Bambu_Sample sample;
    memset(&sample, 0, sizeof(sample));
    int result = runtime->read_sample_fn(runtime->tunnel, &sample);
    if (result == Bambu_would_block) {
        if (out_status != NULL) {
            *out_status = PFHBambuStatusWouldBlock;
        }
        return 0;
    }
    if (result == Bambu_stream_end) {
        if (out_status != NULL) {
            *out_status = PFHBambuStatusStreamEnd;
        }
        return 0;
    }
    if (result != Bambu_success) {
        pfh_set_error(out_error, "Bambu_ReadSample failed");
        return -1;
    }
    if (sample.buffer == NULL || sample.size <= 0) {
        if (out_status != NULL) {
            *out_status = PFHBambuStatusWouldBlock;
        }
        return 0;
    }

    unsigned char* copy = (unsigned char*)malloc((size_t)sample.size);
    if (copy == NULL) {
        pfh_set_error(out_error, "failed to allocate Bambu control buffer");
        return -1;
    }
    memcpy(copy, sample.buffer, (size_t)sample.size);
    if (out_data != NULL) {
        *out_data = copy;
    }
    if (out_size != NULL) {
        *out_size = sample.size;
    }
    return 0;
}

void pfh_bambu_runtime_close(PFHBambuRuntime* runtime) {
    if (runtime == NULL) {
        return;
    }
    if (runtime->tunnel != NULL) {
        if (runtime->close_fn != NULL) {
            runtime->close_fn(runtime->tunnel);
        }
        if (runtime->destroy_fn != NULL) {
            runtime->destroy_fn(runtime->tunnel);
        }
        runtime->tunnel = NULL;
    }
    if (runtime->module != NULL) {
        pfh_close_module(runtime->module);
        runtime->module = NULL;
    }
    free(runtime);
}

void pfh_bambu_runtime_free_bytes(unsigned char* data) {
    if (data != NULL) {
        free(data);
    }
}

void pfh_bambu_runtime_free_string(char* value) {
    if (value != NULL) {
        free(value);
    }
}
