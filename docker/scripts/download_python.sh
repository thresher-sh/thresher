#!/bin/bash
# download_python.sh — Download Python dependencies source-only.

download_python() {
    local target_dir="$1"
    local deps_dir="$2"
    local output_dir="${deps_dir}/python"
    mkdir -p "$output_dir"

    local req_args=()

    if [ -f "${target_dir}/requirements.txt" ]; then
        req_args+=("-r" "${target_dir}/requirements.txt")
    elif [ -f "${target_dir}/pyproject.toml" ] || [ -f "${target_dir}/setup.py" ]; then
        req_args+=("${target_dir}")
    elif [ -f "${target_dir}/Pipfile" ]; then
        # Simple Pipfile extraction — pull package names from [packages]
        local tmp_req="${output_dir}/_pipfile_reqs.txt"
        awk '/^\[packages\]/{flag=1; next} /^\[/{flag=0} flag && /=/' \
            "${target_dir}/Pipfile" | sed 's/ *= *".*"//' > "$tmp_req"
        [ -s "$tmp_req" ] && req_args+=("-r" "$tmp_req")
    fi

    [ ${#req_args[@]} -eq 0 ] && return

    echo "Downloading Python dependencies..."
    pip3 download --no-binary :all: -d "$output_dir" "${req_args[@]}" 2>&1 || {
        echo "WARNING: Some Python packages failed to download"
    }
}
