#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// TorShield SUID helper - execute des commandes root predefinies
// Installe par TorShield au premier lancement : chown root:wheel + chmod 4755
// Le bit SUID permet l'elevation sans prompt a chaque utilisation.

static const char* ALLOWED[] = {
    "/sbin/ifconfig",
    "/sbin/pfctl",
    "/opt/homebrew/sbin/dnsmasq",
    "/usr/local/sbin/dnsmasq",
    "/usr/sbin/dnsmasq",
    NULL,
};

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;

    int allowed = 0;
    for (int i = 0; ALLOWED[i] != NULL; i++) {
        if (strcmp(argv[1], ALLOWED[i]) == 0) { allowed = 1; break; }
    }
    if (!allowed) {
        fprintf(stderr, "ts_helper: commande non autorisee: %s\n", argv[1]);
        return 1;
    }

    if (setuid(0) != 0 || setgid(0) != 0) {
        fprintf(stderr, "ts_helper: elevation root echouee\n");
        return 1;
    }

    execv(argv[1], argv + 1);
    perror("ts_helper: execv");
    return 1;
}
