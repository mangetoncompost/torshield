#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

// TorShield SUID helper - execute des commandes root predefinies
// Installe par TorShield au premier lancement : chown root:wheel + chmod 4755
// Le bit SUID permet l'elevation sans prompt a chaque utilisation.

// Verbe interne generique : lit stdin et ecrit dans un fichier root hardcode.
// O_NOFOLLOW : refuse les symlinks sur la cible finale.
static int write_root_file(const char* path, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, mode);
    if (fd < 0) { perror("ts_helper: open"); return 1; }
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
    "/bin/kill",
    "/usr/bin/pkill",
    NULL,
};

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;

    // Verbe interne write-pf-conf : ecrit /etc/pf.conf depuis stdin
    if (strcmp(argv[1], "write-pf-conf") == 0) {
        if (argc != 2) {
            fprintf(stderr, "ts_helper: write-pf-conf n'accepte pas d'arguments\n");
            return 1;
        }
        if (setuid(0) != 0 || setgid(0) != 0) {
            fprintf(stderr, "ts_helper: elevation root echouee\n");
            return 1;
        }
        return write_root_file("/etc/pf.conf", 0644);
    }

    // Verbe interne write-pf-anchor : ecrit /etc/pf.anchors/com.torshield.killswitch depuis stdin
    if (strcmp(argv[1], "write-pf-anchor") == 0) {
        if (argc != 2) {
            fprintf(stderr, "ts_helper: write-pf-anchor n'accepte pas d'arguments\n");
            return 1;
        }
        if (setuid(0) != 0 || setgid(0) != 0) {
            fprintf(stderr, "ts_helper: elevation root echouee\n");
            return 1;
        }
        return write_root_file("/etc/pf.anchors/com.torshield.killswitch", 0644);
    }

    // Verbe interne rm-pf-anchor : supprime /etc/pf.anchors/com.torshield.killswitch
    if (strcmp(argv[1], "rm-pf-anchor") == 0) {
        if (argc != 2) {
            fprintf(stderr, "ts_helper: rm-pf-anchor n'accepte pas d'arguments\n");
            return 1;
        }
        if (setuid(0) != 0 || setgid(0) != 0) {
            fprintf(stderr, "ts_helper: elevation root echouee\n");
            return 1;
        }
        if (unlink("/etc/pf.anchors/com.torshield.killswitch") != 0 && errno != ENOENT) {
            perror("ts_helper: unlink");
            return 1;
        }
        return 0;
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
