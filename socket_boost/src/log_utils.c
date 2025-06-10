
#include "log_utils.h"

void log_info(const char *format, ...)
{
    FILE *log_file = fopen(LOG_FILE, "a");
    if (!log_file)
    {
        perror("Failed to open log file");
        return;
    }

    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fclose(log_file);
}

void log_error(const char *format, ...)
{
    FILE *error_file = fopen(ERR_FILE, "a");
    if (!error_file)
    {
        perror("Failed to open error file");
        return;
    }

    // print the error on a file
    va_list args;
    va_start(args, format);
    vfprintf(error_file, format, args);
    va_end(args);
    fclose(error_file);

    // also print the error on stderr
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
    fflush(stderr);
}
