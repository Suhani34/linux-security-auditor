#!/usr/bin/env bash

report_file_metadata() {
    local target_file="$1"

    if [[ -e "$target_file" ]]
    then
        stat -c '  %n -> mode=%a owner=%U group=%G permissions=%A' \
            "$target_file" 2>/dev/null
    else
        echo "  $target_file -> not found"
    fi
}

check_file_permissions() {


echo
echo "[FILE PERMISSION SECURITY]"

echo
echo "Critical file metadata:"

report_file_metadata "/etc/passwd"
report_file_metadata "/etc/shadow"
report_file_metadata "/etc/sudoers"
report_file_metadata "/etc/ssh/sshd_config"

echo

if [[ -e /etc/passwd ]]
then

    if find /etc/passwd -perm -0002 -print 2>/dev/null |
       grep -q .
    then
        critical "/etc/passwd is world-writable"
    else
        pass "/etc/passwd is not world-writable"
    fi

    PASSWD_OWNER="$(stat -c '%U' /etc/passwd 2>/dev/null)"

    if [[ "$PASSWD_OWNER" == "root" ]]
    then
        pass "/etc/passwd is owned by root"
    else
        critical "/etc/passwd is not owned by root"
    fi

fi

if [[ -e /etc/shadow ]]
then

    SHADOW_OWNER="$(stat -c '%U' /etc/shadow 2>/dev/null)"

    if [[ "$SHADOW_OWNER" == "root" ]]
    then
        pass "/etc/shadow is owned by root"
    else
        critical "/etc/shadow is not owned by root"
    fi

    if find /etc/shadow -perm -0004 -print 2>/dev/null |
       grep -q .
    then
        critical "/etc/shadow is readable by other users"
    else
        pass "/etc/shadow is not readable by other users"
    fi

    if find /etc/shadow -perm -0002 -print 2>/dev/null |
       grep -q .
    then
        critical "/etc/shadow is world-writable"
    else
        pass "/etc/shadow is not world-writable"
    fi

fi
if [[ -e /etc/sudoers ]]
then

    SUDOERS_OWNER="$(stat -c '%U' /etc/sudoers 2>/dev/null)"

    if [[ "$SUDOERS_OWNER" == "root" ]]
    then
        pass "/etc/sudoers is owned by root"
    else
        critical "/etc/sudoers is not owned by root"
    fi

    if find /etc/sudoers \
        \( -perm -0020 -o -perm -0002 \) \
        -print 2>/dev/null |
        grep -q .
    then
        critical "/etc/sudoers is writable by group or others"
    else
        pass "/etc/sudoers is not writable by group or others"
    fi

fi

if [[ -e /etc/ssh/sshd_config ]]
then

    SSHD_CONFIG_OWNER="$(stat -c '%U' /etc/ssh/sshd_config 2>/dev/null)"

    if [[ "$SSHD_CONFIG_OWNER" == "root" ]]
    then
        pass "SSH server configuration is owned by root"
    else
        warning "SSH server configuration is not owned by root"
    fi

    if find /etc/ssh/sshd_config \
        \( -perm -0020 -o -perm -0002 \) \
        -print 2>/dev/null |
        grep -q .
    then
        critical "SSH server configuration is writable by group or others"
    else
        pass "SSH server configuration is not writable by group or others"
    fi

fi


echo

if [[ "$EUID" -eq 0 ]]
then

    WORLD_WRITABLE_FILES="$(
        find / \
            -xdev \
            -type f \
            -perm -0002 \
            -print \
            2>/dev/null
    )"

    if [[ -z "$WORLD_WRITABLE_FILES" ]]
    then
        WORLD_WRITABLE_FILE_COUNT=0
    else
        WORLD_WRITABLE_FILE_COUNT="$(
            printf '%s\n' "$WORLD_WRITABLE_FILES" |
            sed '/^[[:space:]]*$/d' |
            wc -l
        )"
    fi

    echo "World-writable files     : $WORLD_WRITABLE_FILE_COUNT"

    if [[ "$WORLD_WRITABLE_FILE_COUNT" -eq 0 ]]
    then
        pass "No world-writable regular files detected"
    else
        warning "World-writable regular files detected"

        printf '%s\n' "$WORLD_WRITABLE_FILES" |
        head -n 10 |
        while IFS= read -r writable_file
        do
            echo "  - $writable_file"
        done

        if [[ "$WORLD_WRITABLE_FILE_COUNT" -gt 10 ]]
        then
            echo "  ... additional findings omitted from console output"
        fi
    fi


    WORLD_WRITABLE_DIRS_NO_STICKY="$(
        find / \
            -xdev \
            -type d \
            -perm -0002 \
            ! -perm -1000 \
            -print \
            2>/dev/null
    )"

    if [[ -z "$WORLD_WRITABLE_DIRS_NO_STICKY" ]]
    then
        WORLD_WRITABLE_DIR_COUNT=0
    else
        WORLD_WRITABLE_DIR_COUNT="$(
            printf '%s\n' "$WORLD_WRITABLE_DIRS_NO_STICKY" |
            sed '/^[[:space:]]*$/d' |
            wc -l
        )"
    fi

    echo
    echo "World-writable directories without sticky bit : $WORLD_WRITABLE_DIR_COUNT"
    if [[ "$WORLD_WRITABLE_DIR_COUNT" -eq 0 ]]
    then
        pass "No world-writable directories without sticky bit detected"
    else
        warning "World-writable directories without sticky bit detected"
        add_recommendation "Review world-writable files and directories and remed or temporary locations."

        printf '%s\n' "$WORLD_WRITABLE_DIRS_NO_STICKY" |
        head -n 10 |
        while IFS= read -r writable_dir
        do
            echo "  - $writable_dir"
        done

        if [[ "$WORLD_WRITABLE_DIR_COUNT" -gt 10 ]]
        then
            echo "  ... additional findings omitted from console output"
        fi
    fi
else
   info "System-wide writable-file scan skipped because the auditor is not running as root"
    info "Run with sudo for the complete file-permission audit"

fi
}


check_suid_sgid_security() {
echo
echo "[SUID & SGID SECURITY]"

echo

if [[ "$EUID" -eq 0 ]]
then

    SUID_FILES="$(
        find / \
            -xdev \
            -type f \
            -perm -4000 \
            -print \
            2>/dev/null
    )"

    SGID_FILES="$(
        find / \
            -xdev \
            -type f \
            -perm -2000 \
            -print \
            2>/dev/null
    )"

    if [[ -z "$SUID_FILES" ]]
    then
        SUID_FILE_COUNT=0
    else
        SUID_FILE_COUNT="$(
            printf '%s\n' "$SUID_FILES" |
            sed '/^[[:space:]]*$/d' |
            wc -l
        )"
    fi

    if [[ -z "$SGID_FILES" ]]
    then
        SGID_FILE_COUNT=0
    else
        SGID_FILE_COUNT="$(
            printf '%s\n' "$SGID_FILES" |
            sed '/^[[:space:]]*$/d' |
            wc -l
        )"
    fi

    echo "SUID files : $SUID_FILE_COUNT"
    echo "SGID files : $SGID_FILE_COUNT"

    if [[ "$SUID_FILE_COUNT" -gt 0 ]]
    then

        echo
        echo "SUID files:"

        printf '%s\n' "$SUID_FILES" |
        head -n 15 |
        while IFS= read -r suid_file
        do
            stat -c \
                '  - %n | mode=%a | owner=%U | group=%G | %A' \
                "$suid_file" \
                2>/dev/null
        done

        if [[ "$SUID_FILE_COUNT" -gt 15 ]]
        then
            echo "  ... additional SUID files omitted from console output"
        fi

    fi

    if [[ "$SGID_FILE_COUNT" -gt 0 ]]
    then

        echo
        echo "SGID files:"

        printf '%s\n' "$SGID_FILES" |
        head -n 15 |
        while IFS= read -r sgid_file
        do
            stat -c \
                '  - %n | mode=%a | owner=%U | group=%G | %A' \
                "$sgid_file" \
                2>/dev/null
        done

        if [[ "$SGID_FILE_COUNT" -gt 15 ]]
        then
            echo "  ... additional SGID files omitted from console output"
        fi
     fi
     echo

    WRITABLE_PRIVILEGED_FILES="$(
        find / \
            -xdev \
            -type f \
            \( -perm -4000 -o -perm -2000 \) \
            \( -perm -0020 -o -perm -0002 \) \
            -print \
            2>/dev/null
    )"

    if [[ -z "$WRITABLE_PRIVILEGED_FILES" ]]
    then
        pass "No SUID/SGID files are writable by group or others"
    else

        critical "SUID/SGID file(s) writable by group or others detected"

        printf '%s\n' "$WRITABLE_PRIVILEGED_FILES" |

        while IFS= read -r privileged_file
        do
            stat -c \
                '  - %n | mode=%a | owner=%U | group=%G | %A' \
                "$privileged_file" \
                2>/dev/null
        done

    fi

    UNUSUAL_PRIVILEGED_FILES="$(
        find /home /tmp /var/tmp \
            -xdev \
            -type f \
            \( -perm -4000 -o -perm -2000 \) \
            -print \
            2>/dev/null
    )"

    if [[ -z "$UNUSUAL_PRIVILEGED_FILES" ]]
    then
        pass "No SUID/SGID files detected in common user or temporary directories"
    else

        warning "SUID/SGID files detected in user or temporary directories"

        printf '%s\n' "$UNUSUAL_PRIVILEGED_FILES" |
        while IFS= read -r unusual_file
        do
            stat -c \
                '  - %n | mode=%a | owner=%U | group=%G | %A' \
                "$unusual_file" \
                2>/dev/null
        done

    fi

    NON_ROOT_SUID_FILES=""

    while IFS= read -r suid_file
    do
        [[ -z "$suid_file" ]] && continue

        SUID_OWNER="$(
            stat -c '%U' "$suid_file" 2>/dev/null
        )"

        if [[ -n "$SUID_OWNER" && "$SUID_OWNER" != "root" ]]
        then
            NON_ROOT_SUID_FILES+="$suid_file -> owner=$SUID_OWNER"$'\n'
        fi

    done <<< "$SUID_FILES"

    if [[ -z "$NON_ROOT_SUID_FILES" ]]
    then
        pass "All detected SUID files are owned by root"
    else
        warning "SUID files owned by non-root accounts detected"
        add_recommendation "Review unexpected SUID executables, verify why elevated execution is required , and remove the SUID bit only when it is unnecessary."

        printf '%s' "$NON_ROOT_SUID_FILES"
    fi

    info "SUID/SGID presence alone does not indicate a vulnerability"

else

    info "Complete SUID/SGID discovery skipped because the auditor is not running as root"
    info "Run with sudo for the complete privileged-file audit"

fi

}

check_disk_storage_security() {
echo
echo "[DISK & STORAGE SECURITY]"

echo

if command -v df >/dev/null 2>&1
then

    DISK_WARNING_COUNT=0
    DISK_CRITICAL_COUNT=0

    echo "Filesystem usage:"

    while read -r filesystem blocks used available use_percent mount_point
    do
        [[ "$filesystem" == "Filesystem" ]] && continue
        [[ -z "$filesystem" ]] && continue

        USE_VALUE="${use_percent%\%}"
        if ! [[ "$USE_VALUE" =~ ^[0-9]+$ ]]
        then
            continue
        fi

        printf "  %-28s %-8s %3s%% mounted on %s\n" \
            "$filesystem" \
            "$(numfmt --to=iec --suffix=B --format='%.1f' "${blocks}K" 2>/dev/null || echo "${blocks}k")" \
            "$USE_VALUE" \
            "$mount_point"

        if [[ "$USE_VALUE" -ge 95 ]]
        then
            critical "Filesystem is critically full"
            DISK_CRITICAL_COUNT=$((DISK_CRITICAL_COUNT + 1))

        elif [[ "$USE_VALUE" -ge 80 ]]
        then
            warning "Filesystem usage is high"
            DISK_WARNING_COUNT=$((DISK_WARNING_COUNT + 1))
        fi

    done < <(
        df -Pk \
            -x tmpfs \
            -x devtmpfs \
            2>/dev/null
    )

    echo

    if [[ "$DISK_CRITICAL_COUNT" -gt 0 ]]
    then
        critical "$DISK_CRITICAL_COUNT filesystem(s) are at or above 95% usage"

    elif [[ "$DISK_WARNING_COUNT" -gt 0 ]]
    then
        warning "$DISK_WARNING_COUNT filesystem(s) are at or above 80% usage"
        add_recommendation "Investigate high disk utilization, remove unnecessary data safely and ensure sufficient free space remains for logs and system operations."
    else
        pass "No monitored filesystem is above 80% usage"
    fi

    ROOT_DISK_USAGE="$(
        df -P / 2>/dev/null |
        awk '
            NR == 2 {
                gsub(/%/, "", $5)
                print $5
            }
        '
    )"

    if [[ "$ROOT_DISK_USAGE" =~ ^[0-9]+$ ]]
    then
        info "Root filesystem usage: ${ROOT_DISK_USAGE}%"
    fi
    echo
    echo "Inode usage:"
   INODE_WARNING_COUNT=0
    INODE_CRITICAL_COUNT=0

    while read -r filesystem inodes iused ifree iuse_percent mount_point
    do
        [[ "$filesystem" == "Filesystem" ]] && continue
        [[ -z "$filesystem" ]] && continue

        INODE_USE_VALUE="${iuse_percent%\%}"

        if ! [[ "$INODE_USE_VALUE" =~ ^[0-9]+$ ]]
        then
            continue
        fi

        printf "  %-28s %3s%% mounted on %s\n" \
            "$filesystem" \
            "$INODE_USE_VALUE" \
            "$mount_point"
        if [[ "$INODE_USE_VALUE" -ge 95 ]]
       then
            critical "Inode usage is critically high"
            INODE_CRITICAL_COUNT=$((INODE_CRITICAL_COUNT + 1))

        elif [[ "$INODE_USE_VALUE" -ge 80 ]]
        then
            warning "Inode usage is high"
            INODE_WARNING_COUNT=$((INODE_WARNING_COUNT + 1))

        fi

    done < <(
        df -Pi \
            -x tmpfs \
            -x devtmpfs \
            2>/dev/null
    )

    echo
    if [[ "$INODE_CRITICAL_COUNT" -gt 0 ]]
    then
        critical "$INODE_CRITICAL_COUNT filesystem(s) are at or above 95% inode usage"

    elif [[ "$INODE_WARNING_COUNT" -gt 0 ]]
    then
        warning "$INODE_WARNING_COUNT filesystem(s) are at or above 80% inode usage"

    else
        pass "No monitored filesystem has high inode usage"
    fi

else

    warning "The df command is not available"
    info "Filesystem capacity checks could not be performed"

fi

echo
if command -v findmnt >/dev/null 2>&1
then

    ROOT_MOUNT_INFO="$(
        findmnt \
            -n \
            -o SOURCE,FSTYPE,OPTIONS \
            / \
            2>/dev/null
    )"

    if [[ -n "$ROOT_MOUNT_INFO" ]]
    then
        echo "Root filesystem mount:"
        echo "  $ROOT_MOUNT_INFO"
    else
        info "Unable to determine root filesystem mount options"
    fi

    TMP_EXACT_MOUNT="$(
        findmnt \
            -n \
            -o TARGET \
            /tmp \
            2>/dev/null
    )"

    if [[ "$TMP_EXACT_MOUNT" == "/tmp" ]]
    then

        TMP_MOUNT_INFO="$(
            findmnt \
                -n \
                -o SOURCE,FSTYPE,OPTIONS \
                /tmp \
                2>/dev/null
        )"

        echo
        echo "/tmp separate mount:"
        echo "  $TMP_MOUNT_INFO"
        TMP_OPTIONS="$(
            findmnt \
                -n \
                -o OPTIONS \
                /tmp \
                2>/dev/null
        )"

        if printf '%s\n' "$TMP_OPTIONS" |
           grep -qw nosuid
        then
            pass "/tmp mount uses nosuid"
        else
            info "/tmp mount does not use nosuid"
        fi

        if printf '%s\n' "$TMP_OPTIONS" |
           grep -qw nodev
        then
            pass "/tmp mount uses nodev"
        else
            info "/tmp mount does not use nodev"
        fi

        if printf '%s\n' "$TMP_OPTIONS" |
           grep -qw noexec
        then
            info "/tmp mount uses noexec"
        else
            info "/tmp mount does not use noexec"
        fi

    else

        TMP_BACKING_MOUNT="$(
            findmnt \
                -T /tmp \
                -n \
                -o TARGET,SOURCE,FSTYPE,OPTIONS \
                2>/dev/null
        )"

        echo
        info "/tmp is not a separate filesystem"
        info "/tmp backing mount: $TMP_BACKING_MOUNT"

    fi

else

    info "findmnt is not available; mount-option checks were skipped"

fi

}
