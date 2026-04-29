#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

// Variabilă globală folosită ca flag pentru oprirea buclei principale
volatile sig_atomic_t keep_running = 1;

// Handler pentru SIGINT (Ctrl+C)
void handle_sigint(int sig) {
    // Folosim write în loc de printf în handlerele de semnal pentru siguranță (async-signal-safe)
    write(STDOUT_FILENO, "\n[Monitor] SIGINT received. Shutting down...\n", 45);
    keep_running = 0;
}

// Handler pentru SIGUSR1 (Notificare raport nou)
void handle_sigusr1(int sig) {
    write(STDOUT_FILENO, "[Monitor] Notification: A new report has been added!\n", 53);
}

int main() {
    struct sigaction sa_int, sa_usr1;

    // Configurare handler pentru SIGINT
    sa_int.sa_handler = handle_sigint;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    if (sigaction(SIGINT, &sa_int, NULL) == -1) {
        perror("Error setting up SIGINT handler");
        return 1;
    }

    // Configurare handler pentru SIGUSR1
    sa_usr1.sa_handler = handle_sigusr1;
    sigemptyset(&sa_usr1.sa_mask);
    sa_usr1.sa_flags = 0;
    if (sigaction(SIGUSR1, &sa_usr1, NULL) == -1) {
        perror("Error setting up SIGUSR1 handler");
        return 1;
    }

    // Crearea fișierului ascuns .monitor_pid
    FILE *f = fopen(".monitor_pid", "w");
    if (!f) {
        perror("Failed to create .monitor_pid");
        return 1;
    }
    fprintf(f, "%d\n", getpid());
    fclose(f);

    printf("Monitor started with PID %d. Waiting for signals...\n", getpid());

    // Bucla de așteptare. pause() adoarme procesul până la primirea unui semnal
    while (keep_running) {
        pause();
    }

    // Ștergem fișierul PID la închidere
    unlink(".monitor_pid");
    printf("Monitor cleanly exited. Removed .monitor_pid.\n");

    return 0;
}
