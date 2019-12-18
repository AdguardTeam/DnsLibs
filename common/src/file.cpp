#include <cstdlib>
#include <cstring>
#include <ag_file.h>
#include <ag_utils.h>

#if defined(__linux__) || defined(__LINUX__) || defined(__MACH__)

bool ag::file::is_valid(const handle f) {
    return f >= 0;
}

ag::file::handle ag::file::open(std::string_view path, int flags) {
    return ::open(path.data(), flags, 0666);
}

void ag::file::close(handle f) {
    if (ag::file::is_valid(f)) {
        ::close(f);
    }
}

int ag::file::read(const handle f, char *buf, size_t size) {
    return ::read(f, buf, size);
}

int ag::file::pread(const handle f, char *buf, size_t size, size_t pos) {
    return ::pread(f, buf, size, pos);
}

int ag::file::write(const handle f, const void *buf, size_t size) {
    return ::write(f, buf, size);
}

int ag::file::get_position(const handle f) {
    return ::lseek(f, 0, SEEK_CUR);
}

int ag::file::set_position(handle f, size_t pos) {
    return ::lseek(f, pos, SEEK_SET);
}

int ag::file::get_size(const handle f) {
    struct stat stat;
    return (0 == fstat(f, &stat)) ? stat.st_size : -1;
}

#elif defined(_WIN32)

bool ag::file::is_valid(const handle f) {
    return f >= 0;
}

ag::file::handle ag::file::open(std::string_view path, int flags) {
    return ::_wopen(ag::utils::to_wstring(path).c_str(), flags | _O_BINARY, _S_IWRITE);
}

void ag::file::close(handle f) {
    if (ag::file::is_valid(f)) {
        ::close(f);
    }
}

int ag::file::read(const handle f, char *buf, size_t size) {
    return ::read(f, buf, size);
}

int ag::file::pread(const handle f, char *buf, size_t size, size_t pos) {
    size_t old_pos = get_position(f);
    set_position(f, pos);
    int r = read(f, buf, size);
    set_position(f, old_pos);
    return r;
}

int ag::file::write(const handle f, const void *buf, size_t size) {
    return ::write(f, buf, size);
}

int ag::file::get_position(const handle f) {
    return ::lseek(f, 0, SEEK_CUR);
}

int ag::file::set_position(handle f, size_t pos) {
    return ::lseek(f, pos, SEEK_SET);
}

int ag::file::get_size(const handle f) {
    struct _stat stat;
    return (0 == _fstat(f, &stat)) ? stat.st_size : -1;
}

#else
    #error not supported
#endif

int ag::file::for_each_line(const handle f, line_action action, void *arg) {
    static constexpr size_t MAX_CHUNK_SIZE = 1 * 1024 * 1024;

    int file_size = file::get_size(f);
    if (file_size < 0) {
        return -1;
    }

    size_t chunk_size = std::min(MAX_CHUNK_SIZE, (size_t)file_size);
    std::vector<char> buffer(chunk_size);

    std::string_view line;
    size_t buffer_offset = 0;
    int r;
    size_t file_idx = 0;
    while (0 < (r = file::read(f, &buffer[buffer_offset], chunk_size - buffer_offset))) {
        int from = 0;
        for (int i = 0; i < r; ++i) {
            int c = buffer[i];
            if (c != '\r' && c != '\n') {
                continue;
            }

            size_t line_length = i - from;
            line = { &buffer[from], line_length };
            utils::trim(line);
            if (!action(file_idx + from, line, arg)) {
                return 0;
            }
            from = i + 1;
        }

        buffer_offset = chunk_size - from;
        file_idx += from;
        std::memmove(&buffer[0], &buffer[from], buffer_offset);
    }

    if ((size_t)(file_size - 1) > file_idx) {
        line = { &buffer[0], file_size - file_idx };
        action(file_idx, line, arg);
    }

    return r;
}

std::optional<std::string> ag::file::read_line(const handle f, size_t pos) {
    static constexpr size_t CHUNK_SIZE = 4 * 1024;
    std::vector<char> buffer(CHUNK_SIZE);

    if (0 > file::set_position(f, pos)) {
        return std::nullopt;
    }

    std::string line;
    int r;
    while (0 < (r = file::read(f, &buffer[0], CHUNK_SIZE))) {
        int from = 0;
        int i;
        for (i = 0; i < r; ++i) {
            int c = buffer[i];
            if (c == '\r' || c == '\n') {
                size_t length = i - from;
                line.append(&buffer[from], length);
                break;
            }
        }

        if (i < r) {
            break;
        } else {
            line.append(&buffer[0], r);
        }
    }

    utils::trim(line);
    return line;
}
