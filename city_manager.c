#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

#define MAX_NAME 50
#define MAX_CATEGORY 30
#define MAX_DESC 255
#define MAX_PATH 512

typedef struct {
    int id;
    char inspector_name[MAX_NAME];
    float latitude;
    float longitude;
    char category[MAX_CATEGORY];
    int severity;
    time_t timestamp;
    char description[MAX_DESC];
} Report;

typedef enum {
    ROLE_NONE,
    ROLE_INSPECTOR,
    ROLE_MANAGER
} UserRole;

// Helper: Conversia permisiunilor din mode_t in string ("rw-rw-r--")
void mode_to_string(mode_t mode, char* str) {
    strcpy(str, "---------");
    if (mode & S_IRUSR) str[0] = 'r';
    if (mode & S_IWUSR) str[1] = 'w';
    if (mode & S_IXUSR) str[2] = 'x';
    if (mode & S_IRGRP) str[3] = 'r';
    if (mode & S_IWGRP) str[4] = 'w';
    if (mode & S_IXGRP) str[5] = 'x';
    if (mode & S_IROTH) str[6] = 'r';
    if (mode & S_IWOTH) str[7] = 'w';
    if (mode & S_IXOTH) str[8] = 'x';
}

// Helper: Verificarea accesului bazata strict pe bitii din st_mode si rol
int check_permission(const char* filepath, UserRole role, int need_read, int need_write) {
    struct stat file_stat;
    if (stat(filepath, &file_stat) == -1) {
        if (errno == ENOENT) return 1; // Daca nu exista, il lasam sa curga (va fi creat)
        perror("stat error");
        return 0;
    }

    int can_read = 0, can_write = 0;

    // Managerul foloseste bitii de owner (USR)
    if (role == ROLE_MANAGER) {
        can_read = (file_stat.st_mode & S_IRUSR) ? 1 : 0;
        can_write = (file_stat.st_mode & S_IWUSR) ? 1 : 0;
    }
    // Inspectorul foloseste bitii de group (GRP)
    else if (role == ROLE_INSPECTOR) {
        can_read = (file_stat.st_mode & S_IRGRP) ? 1 : 0;
        can_write = (file_stat.st_mode & S_IWGRP) ? 1 : 0;
    }

    if (need_read && !can_read) {
        fprintf(stderr, "Permission denied: read access required for %s\n", filepath);
        return 0;
    }
    if (need_write && !can_write) {
        fprintf(stderr, "Permission denied: write access required for %s\n", filepath);
        return 0;
    }
    return 1;
}

// Scriere in log EXACT in ordinea: timestamp user role action
void log_action(const char* district, UserRole role, const char* username, const char* action) {
    char filepath[MAX_PATH];
    snprintf(filepath, sizeof(filepath), "%s/logged_district", district);

    // Inspectorii nu pot scrie in log conform 644
    if (!check_permission(filepath, role, 0, 1)) return;

    int fd = open(filepath, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd != -1) {
        char buffer[512];
        char* role_str = (role == ROLE_MANAGER) ? "manager" : "inspector";
        // Ordine corectata conform imaginii: Timestamp, User, Rol, Actiune
        int len = snprintf(buffer, sizeof(buffer), "%ld\t%s\t%s\t%s\n", (long)time(NULL), username, role_str, action);
        write(fd, buffer, len);
        close(fd);
    }
}

// Verificare symlink utilizand lstat
void manage_symlink(const char* district) {
    char symlink_name[MAX_PATH], target[MAX_PATH];
    snprintf(symlink_name, sizeof(symlink_name), "active_reports-%s", district);
    snprintf(target, sizeof(target), "%s/reports.dat", district);

    struct stat st;
    if (lstat(symlink_name, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            struct stat target_st;
            // stat() urmeaza linkul; daca esueaza, e dangling link
            if (stat(symlink_name, &target_st) != 0) {
                printf("Warning: Dangling symlink detected: %s\n", symlink_name);
            }
            return;
        }
    }
    symlink(target, symlink_name);
}

// Initializare district
void init_district_if_needed(const char* district) {
    struct stat st;
    if (stat(district, &st) == -1) {
        if (mkdir(district, 0750) == 0) {
            char path[MAX_PATH];
            int fd;

            snprintf(path, sizeof(path), "%s/reports.dat", district);
            fd = open(path, O_CREAT | O_WRONLY, 0664);
            if (fd != -1) { fchmod(fd, 0664); close(fd); }

            snprintf(path, sizeof(path), "%s/district.cfg", district);
            fd = open(path, O_CREAT | O_WRONLY, 0640);
            if (fd != -1) { fchmod(fd, 0640); close(fd); }

            snprintf(path, sizeof(path), "%s/logged_district", district);
            fd = open(path, O_CREAT | O_WRONLY, 0644);
            if (fd != -1) { fchmod(fd, 0644); close(fd); }
        } else {
            perror("Fatal error creating district directory");
            exit(1);
        }
    }
    manage_symlink(district);
}

// --- Functii AI Assist (Filter) ---
int parse_condition(const char *input, char *field, char *op, char *value) {
    char temp[256];
    strncpy(temp, input, sizeof(temp)-1);
    temp[255] = '\0';

    char *p1 = strchr(temp, ':');
    if (!p1) return 0;
    *p1 = '\0';
    strcpy(field, temp);

    char *p2 = strchr(p1 + 1, ':');
    if (!p2) return 0;
    *p2 = '\0';
    strcpy(op, p1 + 1);
    strcpy(value, p2 + 1);
    return 1;
}

int match_condition(Report *r, const char *field, const char *op, const char *value) {
    if (strcmp(field, "severity") == 0) {
        int v = atoi(value);
        if (strcmp(op, "==") == 0) return r->severity == v;
        if (strcmp(op, "!=") == 0) return r->severity != v;
        if (strcmp(op, ">") == 0)  return r->severity > v;
        if (strcmp(op, ">=") == 0) return r->severity >= v;
        if (strcmp(op, "<") == 0)  return r->severity < v;
        if (strcmp(op, "<=") == 0) return r->severity <= v;
    } else if (strcmp(field, "category") == 0) {
        if (strcmp(op, "==") == 0) return strcmp(r->category, value) == 0;
        if (strcmp(op, "!=") == 0) return strcmp(r->category, value) != 0;
    } else if (strcmp(field, "inspector") == 0) {
        if (strcmp(op, "==") == 0) return strcmp(r->inspector_name, value) == 0;
        if (strcmp(op, "!=") == 0) return strcmp(r->inspector_name, value) != 0;
    }
    return 0;
}
// ----------------------------------

int main(int argc, char *argv[]) {
    UserRole current_role = ROLE_NONE;
    char* current_user = "Unknown";
    char* action = NULL;
    char* target_district = NULL;
    char* extra_args[10];
    int extra_argc = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            current_role = (strcmp(argv[++i], "manager") == 0) ? ROLE_MANAGER : ROLE_INSPECTOR;
        } else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            current_user = argv[++i];
        } else if (strncmp(argv[i], "--", 2) == 0 && strcmp(argv[i], "--role") != 0 && strcmp(argv[i], "--user") != 0) {
            action = argv[i] + 2;
            if (i + 1 < argc) target_district = argv[++i];
            while (i + 1 < argc && strncmp(argv[i+1], "--", 2) != 0 && extra_argc < 10) {
                extra_args[extra_argc++] = argv[++i];
            }
        }
    }

    if (current_role == ROLE_NONE || !target_district || !action) {
        fprintf(stderr, "Usage: city_manager --role <role> --user <user> --<action> <district> [args...]\n");
        return 1;
    }

    init_district_if_needed(target_district);
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/reports.dat", target_district);

    // ACTION: ADD
    if (strcmp(action, "add") == 0) {
        if (!check_permission(path, current_role, 0, 1)) return 1;

        Report new_report;
        memset(&new_report, 0, sizeof(Report)); // curatam cu 0 pentru HEX curat

        // Atribuim id si detalii logice (nu apar in screenshot, dar sunt necesare intern)
        new_report.id = (int)time(NULL) % 100000;
        strncpy(new_report.inspector_name, current_user, MAX_NAME - 1);
        new_report.timestamp = time(NULL);

        // --- Afisari exact ca in screenshot-ul tau ---
        printf("X: ");
        if (scanf("%f", &new_report.latitude) != 1) return 1;

        printf("Y: ");
        if (scanf("%f", &new_report.longitude) != 1) return 1;

        printf("Category (road/lighting/flooding/other): ");
        if (scanf("%29s", new_report.category) != 1) return 1;

        printf("Severity level (1/2/3):");
        if (scanf("%d", &new_report.severity) != 1) return 1;

        printf("Description:");
        // Consumam caracterul newline lasat in buffer
        int c; while ((c = getchar()) != '\n' && c != EOF);

        if (fgets(new_report.description, MAX_DESC, stdin)) {
            new_report.description[strcspn(new_report.description, "\n")] = 0;
        }

        int fd = open(path, O_WRONLY | O_APPEND);
        if (fd != -1) {
            write(fd, &new_report, sizeof(Report));
            close(fd);
            log_action(target_district, current_role, current_user, "add");
            // FARA afisari suplimentare! Terminalul tau isi va da direct exit aici ca in poza.
        }
    }
    // ACTION: LIST
    else if (strcmp(action, "list") == 0) {
        if (!check_permission(path, current_role, 1, 0)) return 1;

        struct stat st;
        if (stat(path, &st) == 0) {
            char perm[10];
            mode_to_string(st.st_mode, perm);
            printf("File info: %s | Size: %ld bytes | Last mod: %s", perm, st.st_size, ctime(&st.st_mtime));
        }

        int fd = open(path, O_RDONLY);
        if (fd != -1) {
            Report r;
            printf("--- Reports in %s ---\n", target_district);
            while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
                printf("[%d] %s | Sev: %d | By: %s\n", r.id, r.category, r.severity, r.inspector_name);
            }
            close(fd);
            log_action(target_district, current_role, current_user, "list");
        }
    }
    // ACTION: VIEW
    else if (strcmp(action, "view") == 0 && extra_argc > 0) {
        if (!check_permission(path, current_role, 1, 0)) return 1;

        int target_id = atoi(extra_args[0]);
        int fd = open(path, O_RDONLY);
        if (fd != -1) {
            Report r;
            while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
                if (r.id == target_id) {
                    printf("ID: %d\nInspector: %s\nCoords: %.4f, %.4f\nCategory: %s\nSeverity: %d\nTime: %sDescription: %s\n",
                           r.id, r.inspector_name, r.latitude, r.longitude, r.category, r.severity, ctime(&r.timestamp), r.description);
                    break;
                }
            }
            close(fd);
            log_action(target_district, current_role, current_user, "view");
        }
    }
    // ACTION: REMOVE_REPORT
    else if (strcmp(action, "remove_report") == 0 && extra_argc > 0) {
        if (current_role != ROLE_MANAGER) {
            fprintf(stderr, "Permission denied: Only managers can remove reports.\n");
            return 1;
        }

        int target_id = atoi(extra_args[0]);
        int fd = open(path, O_RDWR);
        if (fd == -1) return 1;

        Report r;
        off_t read_offset = 0;
        int found = 0;

        while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
            if (r.id == target_id) {
                found = 1;
                break;
            }
            read_offset += sizeof(Report);
        }

        if (found) {
            off_t write_offset = read_offset;
            read_offset += sizeof(Report);

            while (lseek(fd, read_offset, SEEK_SET) != -1 && read(fd, &r, sizeof(Report)) == sizeof(Report)) {
                lseek(fd, write_offset, SEEK_SET);
                write(fd, &r, sizeof(Report));
                read_offset += sizeof(Report);
                write_offset += sizeof(Report);
            }

            ftruncate(fd, write_offset);
            printf("Report %d successfully removed.\n", target_id);
            log_action(target_district, current_role, current_user, "remove_report");
        } else {
            printf("Report %d not found.\n", target_id);
        }
        close(fd);
    }
    // ACTION: UPDATE_THRESHOLD
    else if (strcmp(action, "update_threshold") == 0 && extra_argc > 0) {
        if (current_role != ROLE_MANAGER) {
            fprintf(stderr, "Permission denied: Only managers can update threshold.\n");
            return 1;
        }

        char cfg_path[MAX_PATH];
        snprintf(cfg_path, sizeof(cfg_path), "%s/district.cfg", target_district);

        struct stat st;
        if (stat(cfg_path, &st) == 0) {
            if ((st.st_mode & 0777) != 0640) {
                fprintf(stderr, "Diagnostic error: district.cfg permissions altered. Expected 640.\n");
                return 1;
            }
        }

        int fd = open(cfg_path, O_WRONLY | O_TRUNC);
        if (fd != -1) {
            write(fd, extra_args[0], strlen(extra_args[0]));
            write(fd, "\n", 1);
            close(fd);
            printf("Threshold updated to %s.\n", extra_args[0]);
            log_action(target_district, current_role, current_user, "update_threshold");
        }
    }
    // ACTION: FILTER
    else if (strcmp(action, "filter") == 0 && extra_argc > 0) {
        if (!check_permission(path, current_role, 1, 0)) return 1;

        int fd = open(path, O_RDONLY);
        if (fd != -1) {
            Report r;
            char field[30], op[5], value[30];

            printf("--- Filtered Reports ---\n");
            while (read(fd, &r, sizeof(Report)) == sizeof(Report)) {
                int match_all = 1;
                for (int i = 0; i < extra_argc; i++) {
                    if (parse_condition(extra_args[i], field, op, value)) {
                        if (!match_condition(&r, field, op, value)) {
                            match_all = 0;
                            break;
                        }
                    } else {
                        fprintf(stderr, "Failed to parse condition: %s\n", extra_args[i]);
                        match_all = 0; break;
                    }
                }

                if (match_all) {
                    printf("Match: [%d] %s | Sev: %d | By: %s\n", r.id, r.category, r.severity, r.inspector_name);
                }
            }
            close(fd);
            log_action(target_district, current_role, current_user, "filter");
        }
    }

    return 0;
}
