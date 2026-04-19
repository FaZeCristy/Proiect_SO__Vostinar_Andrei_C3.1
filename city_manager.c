#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

#define MAX_NAME 50
#define MAX_CATEGORY 30
#define MAX_DESC 255
#define MAX_PATH 512

// Structura pentru fisierul binar
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

// Enum pentru roluri
typedef enum {
    ROLE_NONE,
    ROLE_INSPECTOR,
    ROLE_MANAGER
} UserRole;

// Helper pentru conversia permisiunilor
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

// Verificarea permisiunilor
int check_permission(const char* filepath, UserRole role, int need_read, int need_write) {
    struct stat file_stat;
    if (stat(filepath, &file_stat) == -1) {
        if (errno == ENOENT) return 1;
        perror("stat error");
        return 0;
    }

    int can_read = 0, can_write = 0;
    if (role == ROLE_MANAGER) {
        can_read = (file_stat.st_mode & S_IRUSR) ? 1 : 0;
        can_write = (file_stat.st_mode & S_IWUSR) ? 1 : 0;
    } else if (role == ROLE_INSPECTOR) {
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

// Crearea structurii de directoare
void init_district_if_needed(const char* district) {
    if (mkdir(district, 0750) == 0) {
        char path[MAX_PATH];
        FILE *f;

        snprintf(path, sizeof(path), "%s/reports.dat", district);
        f = fopen(path, "wb"); if (f) fclose(f);
        chmod(path, 0664);

        snprintf(path, sizeof(path), "%s/district.cfg", district);
        f = fopen(path, "w"); if (f) fclose(f);
        chmod(path, 0640);

        snprintf(path, sizeof(path), "%s/logged_district", district);
        f = fopen(path, "w"); if (f) fclose(f);
        chmod(path, 0644);
    } else if (errno != EEXIST) {
        perror("Fatal error creating directory");
        exit(1);
    }
}

// Functia actualizata
void log_action_safe(const char* district, UserRole role, const char* username, const char* action) {
    char filepath[MAX_PATH];
    snprintf(filepath, sizeof(filepath), "%s/logged_district", district);

    if (!check_permission(filepath, role, 0, 1)) {
        // Daca e inspector, conform permisiunilor 0644, nu are voie să scrie în log.
        // Intoarcem pur si simplu return pentru a refuza tacut actiunea de scriere.
        return;
    }

    FILE* log_file = fopen(filepath, "a");
    if (log_file) {
        char* role_str = (role == ROLE_MANAGER) ? "manager" : "inspector";
        // Format: <timestamp> <tab> <user> <tab> <role> <tab> <action>
        fprintf(log_file, "%ld\t%s\t%s\t%s\n", (long)time(NULL), username, role_str, action);
        fclose(log_file);
    }
}

int main(int argc, char *argv[]) {
    UserRole current_role = ROLE_NONE;
    char* current_user = "Unknown";
    char* action = NULL;
    char* target_district = NULL;

    // Parsam argumentele
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            if (strcmp(argv[i+1], "inspector") == 0) current_role = ROLE_INSPECTOR;
            else if (strcmp(argv[i+1], "manager") == 0) current_role = ROLE_MANAGER;
            i++;
        }
        else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            current_user = argv[i+1];
            i++;
        }
        else if (strcmp(argv[i], "--add") == 0 && i + 1 < argc) {
            action = "add";
            target_district = argv[i+1];
            i++;
        }
    }

    if (current_role == ROLE_NONE || target_district == NULL || action == NULL) {
        fprintf(stderr, "Invalid arguments.\n");
        return 1;
    }

    // Cream directoarele daca nu exista (silentios)
    init_district_if_needed(target_district);

    if (strcmp(action, "add") == 0) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s/reports.dat", target_district);

        if (!check_permission(path, current_role, 0, 1)) return 1;

        // Declaram si curatam complet structura cu 0 pentru un HEX dump `xxd` curat
        Report new_report;
        memset(&new_report, 0, sizeof(Report));

        // Setam valorile implicite
        new_report.id = 1; // ID implicit deocamdata
        strncpy(new_report.inspector_name, current_user, MAX_NAME - 1);
        new_report.timestamp = time(NULL);


        printf("X: ");
        if (scanf("%f", &new_report.latitude) != 1) return 1;

        printf("Y: ");
        if (scanf("%f", &new_report.longitude) != 1) return 1;

        printf("Category (road/lighting/flooding/other): ");
        if (scanf("%29s", new_report.category) != 1) return 1;

        printf("Severity level (1/2/3):");
        if (scanf("%d", &new_report.severity) != 1) return 1;

        printf("Description:");

        // Consumam caracterul newline '\n' lasat in buffer de scanf-ul anterior
        int c;
        while ((c = getchar()) != '\n' && c != EOF);

        // Citim textul descrierii, care poate contine spatii (ex: "Road closed")
        if (fgets(new_report.description, MAX_DESC, stdin) != NULL) {
            // Eliminam newline-ul pus de fgets la final
            new_report.description[strcspn(new_report.description, "\n")] = 0;
        }

        // Scriem în fisierul binar
        FILE* f = fopen(path, "ab");
        if (!f) {
            perror("Error opening reports.dat");
            return 1;
        }
        fwrite(&new_report, sizeof(Report), 1, f);
        fclose(f);

        // Logam actiunea cu termenul scurt "add"
        log_action_safe(target_district, current_role, current_user, "add");
    }

    return 0;
}
