#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

// TorShield SUID helper - execute des commandes root predefinies
// Installe par TorShield au premier lancement : chown root:wheel + chmod 4755
// Le bit SUID permet l'elevation sans prompt a chaque utilisation.

// Verbe interne : lit stdin et ecrit dans /etc/pf.conf (chemin hardcode, non injectable).
// Remplace l'usage precedent de tee (GTFOBins : tee SUID = ecriture arbitraire root).
static int write_pf_conf(void) {
    // O_NOFOLLOW : refuse les symlinks sur la cible finale
    int fd = open("/etc/pf.conf", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd < 0) { perror("ts_helper: open /etc/pf.conf"); return 1; }
    char buf[4096];
    ssize_t n;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        if (write(fd, buf, (size_t)n) != n) {
            perror("ts_helper: write");
            close(fd);
            return 1;
        }
    }
    close(fd);
    return 0;
}

static const char* ALLOWED[] = {
    "/sbin/ifconfig",
    "/sbin/pfctl",
    "/opt/homebrew/sbin/dnsmasq",
    "/usr/local/sbin/dnsmasq",
    "/usr/sbin/dnsmasq",
    "kill",
    "/usr/bin/pkill",
    NULL,
};

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;

    // Verbe interne write-pf-conf : aucun argument supplementaire accepte
    if (strcmp(argv[1], "write-pf-conf") == 0) {
        if (argc != 2) {
            fprintf(stderr, "ts_helper: write-pf-conf n'accepte pas d'arguments\n");
            return 1;
        }
        if (setuid(0) != 0 || setgid(0) != 0) {
            fprintf(stderr, "ts_helper: elevation root echouee\n");
            return 1;
        }
        return write_pf_conf();
    }

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
