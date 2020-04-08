#pragma once


#include <string_view>
#include <string>
#include <optional>
#include <cstdlib>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(__linux__) || defined(__LINUX__) || defined(__MACH__)
    #include <unistd.h>
#elif defined(_WIN32)
    #include <windows.h>
    #include <io.h>
#endif


namespace ag::file {

    using handle = int;
    static constexpr int INVALID_HANDLE = -1;

#if defined(__linux__) || defined(__LINUX__) || defined(__MACH__)
    enum flags {
        RDONLY = O_RDONLY,
        WRONLY = O_WRONLY,
        RDWR = O_RDWR,
        CREAT = O_CREAT,
    };
#elif defined(_WIN32)
    enum flags {
        RDONLY = _O_RDONLY,
        WRONLY = _O_WRONLY,
        RDWR = _O_RDWR,
        CREAT = _O_CREAT,
    };
#else
    #error not supported
#endif


    /**
     * @brief      Check if file handle is valid
     * @param[in]  f     file handle
     * @return     True if valid, false otherwise
     */
    bool is_valid(const handle f);

    /**
     * @brief      Open file by path
     * @param[in]  path   system path
     * @param[in]  flags  file mode flags
     * @return     Handle of file
     */
    handle open(std::string_view path, int flags);

    /**
     * @brief      Close file
     * @param[in]  f     file handle
     */
    void close(handle f);

    /**
     * @brief      Read data from file
     * @param[in]  f     file handle
     * @param      buf   buffer to store read data
     * @param[in]  size  buffer size
     * @return     Number of read bytes (<0 in case of error)
     */
    int read(const handle f, char *buf, size_t size);

    /**
     * @brief      Read data from file with given offset
     *             (file offset is not changed)
     * @param[in]  f     file handle
     * @param      buf   buffer to store read data
     * @param[in]  size  buffer size
     * @param[in]  pos   file offset
     * @return     Number of read bytes (<0 in case of error)
     */
    int pread(const handle f, char *buf, size_t size, size_t pos);

    /**
     * @brief      Write buffer in file
     * @param[in]  f     file handle
     * @param[in]  buf   data to be written
     * @param[in]  size  data size
     * @return     Number of written bytes (<0 in case of error)
     */
    int write(const handle f, const void *buf, size_t size);

    /**
     * @brief      Read a line at given offset from file
     * @param[in]  f     file handle
     * @param[in]  pos   file offset
     * @return     Read line, or nullopt in case of error
     */
    std::optional<std::string> read_line(const handle f, size_t pos);

    /**
     * @brief      Get current file position
     * @param[in]  f     file handle
     * @return     Current position (<0 in case of error)
     */
    int get_position(const handle f);

    /**
     * @brief      Sets file position
     * @param[in]  f     file handle
     * @param[in]  pos   new position
     * @return     New postion value (<0 in case of error)
     */
    int set_position(const handle f, size_t pos);

    /**
     * @brief      Get file size
     * @param[in]  f     file handle
     * @return     File size (<0 in case of error)
     */
    int get_size(const handle f);

    /**
     * Function to be called from `for_each_line`
     * @param file position of read line
     * @param read line
     * @param user argument
     * @return true file reading loop continues
     *         false the loop stops
     */
    using line_action = bool (*)(uint32_t, std::string_view, void *);

    /**
     * @brief      Apply user function to each line in file, while user function return true
     *             or eof not met
     * @param[in]  f       file handle
     * @param[in]  action  user function
     * @param      arg     user argument
     *
     * @return     >=0 in case of success,
     *             <0 otherwise
     */
    int for_each_line(const handle f, line_action action, void *arg);

} // namespace ag::file
