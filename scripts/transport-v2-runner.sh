#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: transport-v2-runner.sh <doctor|provision|deploy|run-formal|collect|cleanup> --config <private-0600-json> --sha <exact-sha> [--base-sha <sha>] [--output <path>]" >&2
  exit 2
}

[[ $# -ge 1 ]] || usage
action=$1
shift
case "$action" in
  doctor | provision | deploy | run-formal | collect | cleanup) ;;
  *) usage ;;
esac

config=
source_sha=
base_sha=
output_path=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) [[ $# -ge 2 ]] || usage; config=$2; shift 2 ;;
    --sha) [[ $# -ge 2 ]] || usage; source_sha=$2; shift 2 ;;
    --base-sha) [[ $# -ge 2 ]] || usage; base_sha=$2; shift 2 ;;
    --output) [[ $# -ge 2 ]] || usage; output_path=$2; shift 2 ;;
    *) usage ;;
  esac
done

[[ $source_sha =~ ^[0-9a-f]{40}$ ]] || usage
[[ -n $config && $config == /* && -f $config && ! -L $config ]] || usage
if [[ -n $base_sha ]]; then
  [[ $base_sha =~ ^[0-9a-f]{40}$ && $base_sha != "$source_sha" ]] || usage
fi
case "$action" in
  doctor | run-formal | collect) [[ -n $base_sha ]] || usage ;;
esac

file_mode() {
  stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

[[ $(file_mode "$config") == 600 ]] || { echo "runner config must be mode 0600" >&2; exit 2; }
jq -e --arg action "$action" '
  .schema == "flowersec-remote-runner-config-v1" and
  ((keys | sort) == (["artifact_root","dependency_urls","guest_identity_file","guest_known_hosts_file","guest_port",
      "guest_architecture","guest_effective_cpus","guest_launcher_argv","guest_launcher_executable","guest_legacy_pid_file",
      "guest_repo","guest_root","guest_target","guest_vm_name","host_agent_path","host_config_path","host_request_path","lxc_executable","lxc_name",
      "lxc_root","proxy_url","runner_id","schema","scp_executable","ssh_executable","ssh_target","state_path"] | sort) or
    (($action == "collect" or $action == "cleanup") and
      ((keys | sort) == (["artifact_root","dependency_urls","guest_identity_file","guest_known_hosts_file","guest_port",
          "guest_repo","guest_root","guest_target","host_agent_path","host_config_path","host_request_path","lxc_executable","lxc_name",
          "lxc_root","proxy_url","runner_id","schema","scp_executable","ssh_executable","ssh_target","state_path"] | sort) or
       (keys | sort) == (["artifact_root","dependency_urls","guest_identity_file","guest_known_hosts_file","guest_port",
          "guest_repo","guest_root","guest_target","host_agent_path","host_config_path","host_request_path","lxc_name",
          "lxc_root","proxy_url","runner_id","schema","scp_executable","ssh_executable","ssh_target","state_path"] | sort)))) and
  ([.runner_id,.ssh_target,.ssh_executable,.scp_executable,.host_agent_path,.host_config_path,.host_request_path,
    .state_path,(.lxc_executable // "/snap/bin/lxc"),.lxc_name,.lxc_root,.guest_target,.guest_identity_file,.guest_known_hosts_file,
    .guest_root,.guest_repo,.artifact_root,.proxy_url] | all(type == "string" and length > 0)) and
  ((has("guest_architecture") | not) or
    (.guest_architecture | IN("amd64","arm64")) and .guest_effective_cpus == 8 and
    (.guest_launcher_executable | type == "string" and startswith("/")) and
    (.guest_legacy_pid_file | type == "string" and startswith("/")) and
    (.guest_vm_name | type == "string" and test("^[A-Za-z0-9_.-]+$")) and
    (.guest_launcher_argv | type == "array" and length > 0 and all(type == "string"))) and
  (.guest_port | type == "number" and . >= 1 and . <= 65535) and
  (.dependency_urls | type == "array" and length > 0 and all(type == "string" and startswith("https://")))
' "$config" >/dev/null || { echo "runner config is invalid" >&2; exit 2; }
jq -e '(.lxc_executable // "/snap/bin/lxc") | startswith("/")' "$config" >/dev/null || { echo "runner LXC executable must be absolute" >&2; exit 2; }
if [[ $action == collect ]]; then
  [[ $output_path == /* && ! -L $output_path && -d $(dirname "$output_path") ]] || {
    echo "collect requires an absolute local output path with an existing parent" >&2
    exit 2
  }
fi

script_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repository=$(cd "$script_root/.." && pwd -P)
agent_source=$script_root/transport-v2-runner-agent.sh
host_helper_source=$script_root/transport-v2-runner-host.py
proxy_source=$script_root/transport-v2-runner-proxy.py
template_source=$script_root/flowersec-formal@.service
kvm_helper_source=$script_root/transport-v2-runner-kvm.py
kvm_template_source=$script_root/flowersec-kvm-guest@.service
[[ -x $agent_source && -x $host_helper_source && -f $proxy_source && -f $template_source && -x $kvm_helper_source && -f $kvm_template_source &&
  ! -L $agent_source && ! -L $host_helper_source && ! -L $proxy_source && ! -L $template_source && ! -L $kvm_helper_source && ! -L $kvm_template_source ]] || {
  echo "checked-in runner agents are unavailable" >&2
  exit 2
}
runner_id=$(jq -r '.runner_id' "$config")
ssh_target=$(jq -r '.ssh_target' "$config")
ssh_executable=$(jq -r '.ssh_executable' "$config")
scp_executable=$(jq -r '.scp_executable' "$config")
[[ -x $ssh_executable && -x $scp_executable && $ssh_executable == /* && $scp_executable == /* ]] || {
  echo "runner SSH executables must be absolute executable paths" >&2
  exit 2
}
host_agent_path=$(jq -r '.host_agent_path' "$config")
host_config_path=$(jq -r '.host_config_path' "$config")
host_request_path=$(jq -r '.host_request_path' "$config")
state_path=$(jq -r '.state_path' "$config")
for value in "$runner_id" "$ssh_target" "$host_agent_path" "$host_config_path" "$host_request_path" "$(jq -r '.lxc_executable // "/snap/bin/lxc"' "$config")"; do
  [[ $value =~ ^[A-Za-z0-9_@./:-]+$ ]] || { echo "runner config contains an unsafe remote token" >&2; exit 2; }
done
host_remote_root=$(dirname "$host_agent_path")
[[ $(dirname "$host_config_path") == "$host_remote_root" && $(dirname "$host_request_path") == "$host_remote_root" ]] || {
  echo "runner host agent, config, and request must share one private directory" >&2
  exit 2
}
[[ $state_path == /* && $(dirname "$state_path") != "$state_path" ]] || usage
install -d -m 0700 "$(dirname "$state_path")"
if [[ -e $state_path || -L $state_path ]]; then
  [[ -f $state_path && ! -L $state_path && $(file_mode "$state_path") == 600 ]] || {
    echo "runner state must be a private regular file" >&2
    exit 2
  }
fi

config_sha256=$(sha256_file "$config")
if [[ $(git -C "$repository" rev-parse HEAD) != "$source_sha" ]]; then
  [[ ($action == collect || $action == cleanup) && -f $state_path && ! -L $state_path ]] &&
    jq -e --arg sha "$source_sha" --arg config_sha256 "$config_sha256" '
      .config_sha256 == $config_sha256 and .actions["run-formal"].source_sha == $sha
    ' "$state_path" >/dev/null 2>&1 || {
      echo "runner SHA must match the current exact checkout outside exact-state recovery" >&2
      exit 3
    }
fi
case "$action" in
  doctor)
    jq -e --arg sha "$source_sha" --arg config_sha256 "$config_sha256" '
      .config_sha256 == $config_sha256 and .actions.provision.status == "GREEN" and .actions.provision.source_sha == $sha and
      .actions.deploy.status == "GREEN" and .actions.deploy.source_sha == $sha
    ' "$state_path" >/dev/null 2>&1 || { echo "doctor requires completed provision and exact-SHA deploy receipts" >&2; exit 5; }
    ;;
  run-formal)
    jq -e --arg sha "$source_sha" --arg base "$base_sha" --arg config_sha256 "$config_sha256" '
      .config_sha256 == $config_sha256 and .actions.doctor.status == "GREEN" and
      .actions.doctor.source_sha == $sha and .actions.doctor.base_sha == $base
    ' "$state_path" >/dev/null 2>&1 || { echo "run-formal requires the exact-SHA/base doctor receipt" >&2; exit 5; }
    ;;
  collect)
    jq -e --arg sha "$source_sha" --arg config_sha256 "$config_sha256" '
      .config_sha256 == $config_sha256 and .actions["run-formal"].status == "RUNNING" and
      .actions["run-formal"].source_sha == $sha
    ' "$state_path" >/dev/null 2>&1 || { echo "collect requires the unique formal start receipt" >&2; exit 5; }
    ;;
esac
if [[ -f $state_path && ! -L $state_path ]] &&
  jq -e --arg action "$action" --arg sha "$source_sha" --arg base "$base_sha" --arg output "$output_path" --arg config_sha256 "$config_sha256" '
    .schema == "flowersec-remote-runner-state-v1" and .config_sha256 == $config_sha256 and
    .actions[$action].source_sha == $sha and
    (($action != "doctor" and $action != "run-formal" and $action != "collect") or .actions[$action].base_sha == $base) and
    ($action != "collect" or .actions[$action].local_archive_path == $output) and
    (.actions[$action].status == "GREEN" or ($action == "run-formal" and .actions[$action].status == "RUNNING"))
  ' "$state_path" >/dev/null 2>&1; then
  if [[ $action == collect ]]; then
    receipt_sha256=$(jq -r '.actions.collect.archive_sha256' "$state_path")
    [[ -f $output_path && ! -L $output_path && $receipt_sha256 =~ ^[0-9a-f]{64}$ && $(sha256_file "$output_path") == "$receipt_sha256" ]] || {
      echo "collected closure no longer matches its exact receipt" >&2
      exit 4
    }
  fi
  jq -c --arg action "$action" '.actions[$action]' "$state_path"
  exit 0
fi
if [[ $action == collect && (-e $output_path || -L $output_path) ]]; then
  echo "collect requires a fresh output path unless its exact GREEN receipt is resumed" >&2
  exit 2
fi
request=$(mktemp "$(dirname "$state_path")/.transport-v2-runner-request.XXXXXX.json")
bundle=
collected_temp=
cleanup_local() {
  rm -f -- "$request"
  if [[ -n $bundle ]]; then rm -f -- "$bundle"; fi
  if [[ -n $collected_temp ]]; then rm -f -- "$collected_temp"; fi
}
trap cleanup_local EXIT HUP INT TERM
chmod 0600 "$request"

host_bundle_path=$(dirname "$host_agent_path")/$source_sha.bundle
bundle_sha256=
archive_sha256=
agent_sha256=$(sha256_file "$agent_source")
host_helper_sha256=$(sha256_file "$host_helper_source")
proxy_sha256=$(sha256_file "$proxy_source")
template_sha256=$(sha256_file "$template_source")
kvm_helper_sha256=$(sha256_file "$kvm_helper_source")
kvm_template_sha256=$(sha256_file "$kvm_template_source")
if [[ $action == deploy ]]; then
  bundle=$(mktemp "$(dirname "$state_path")/.transport-v2-runner-bundle.XXXXXX")
  git -C "$repository" bundle create "$bundle" HEAD
  chmod 0600 "$bundle"
  git -C "$repository" bundle verify "$bundle" >/dev/null
  bundle_sha256=$(sha256_file "$bundle")
fi
if [[ $action == cleanup && -f $state_path && ! -L $state_path ]]; then
  collected_path=$(jq -r '.actions.collect.local_archive_path // ""' "$state_path")
  recorded_archive_sha256=$(jq -r '.actions.collect.archive_sha256 // ""' "$state_path")
  if [[ -n $collected_path || -n $recorded_archive_sha256 ]]; then
    [[ $collected_path == /* && -f $collected_path && ! -L $collected_path && $recorded_archive_sha256 =~ ^[0-9a-f]{64}$ ]] || {
      echo "cleanup requires the checksummed local collection receipt" >&2
      exit 4
    }
    [[ $(sha256_file "$collected_path") == "$recorded_archive_sha256" ]] || {
      echo "cleanup collection digest mismatch" >&2
      exit 4
    }
    archive_sha256=$recorded_archive_sha256
  fi
fi

jq -n \
  --arg schema flowersec-remote-runner-request-v1 \
  --arg action "$action" \
  --arg source_sha "$source_sha" \
  --arg base_sha "$base_sha" \
  --arg output_path "$output_path" \
  --arg config_sha256 "$config_sha256" \
  --arg bundle_sha256 "$bundle_sha256" \
  --arg archive_sha256 "$archive_sha256" \
  --arg agent_sha256 "$agent_sha256" \
  --arg host_helper_sha256 "$host_helper_sha256" \
  --arg proxy_sha256 "$proxy_sha256" \
  --arg template_sha256 "$template_sha256" \
  --arg kvm_helper_sha256 "$kvm_helper_sha256" \
  --arg kvm_template_sha256 "$kvm_template_sha256" \
  --arg host_bundle_path "$host_bundle_path" \
  '{schema:$schema,action:$action,source_sha:$source_sha,base_sha:$base_sha,output_path:$output_path,
    config_sha256:$config_sha256,bundle_sha256:$bundle_sha256,archive_sha256:$archive_sha256,
    agent_sha256:$agent_sha256,host_helper_sha256:$host_helper_sha256,proxy_sha256:$proxy_sha256,template_sha256:$template_sha256,
    kvm_helper_sha256:$kvm_helper_sha256,kvm_template_sha256:$kvm_template_sha256,
    host_bundle_path:$host_bundle_path}' >"$request"

persist_failure() {
  local payload=$1 status_code=$2 failure_state existing
  failure_state=$(mktemp "$(dirname "$state_path")/.transport-v2-runner-failure.XXXXXX.json")
  existing='{"schema":"flowersec-remote-runner-state-v1","actions":{}}'
  if [[ -f $state_path && ! -L $state_path ]]; then existing=$(<"$state_path"); fi
  jq -n --argjson existing "$existing" --argjson failure "$payload" \
    --arg config_sha256 "$config_sha256" --arg updated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg action "$action" \
    '{schema:"flowersec-remote-runner-state-v1",config_sha256:$config_sha256,updated_at:$updated_at,
      actions:($existing.actions // {}),last_failure:$failure} |
     if $action != "cleanup" then del(.actions.cleanup) else . end |
     if $action == "collect" then .actions[$action]=$failure else . end' >"$failure_state"
  chmod 0600 "$failure_state"
  mv -f -- "$failure_state" "$state_path"
  printf '%s\n' "$payload" >&2
  exit "$status_code"
}

reachability_failure() {
  jq -cn --arg action "$action" --arg sha "$source_sha" --arg base "$base_sha" \
    '{schema:"flowersec-remote-runner-result-v1",status:"RED",action:$action,source_sha:$sha,base_sha:$base,
      classification:"unreachable",check_id:"runner_reachability",message:"remote runner transport failed before a structured result"}'
}

validate_remote_result() {
  jq -e --arg action "$action" --arg sha "$source_sha" --arg base "$base_sha" '
    .schema == "flowersec-remote-runner-result-v1" and .action == $action and .source_sha == $sha and
    .base_sha == $base and (.classification | type == "string") and (.check_id | type == "string") and
    (.message | type == "string") and (.status == "GREEN" or .status == "RUNNING" or .status == "RED") and
    if $action != "collect" or .status == "RUNNING" or (has("archive_path") | not) then
      (keys | sort) == (["action","base_sha","check_id","classification","message","schema","source_sha","status"] | sort)
    else
      (keys | sort) == (["action","archive_path","archive_sha256","base_sha","check_id","classification",
        "host_archive_path","lxd_archive_path","message","schema","source_sha","status"] | sort)
    end
  ' <<<"$1" >/dev/null 2>&1
}

run_transport() {
  local transport_status
  set +e
  "$@"
  transport_status=$?
  set -e
  if [[ $transport_status != 0 ]]; then persist_failure "$(reachability_failure)" 20; fi
}

run_transport "$ssh_executable" -n -o ConnectTimeout=10 -o ConnectionAttempts=1 "$ssh_target" install -d -m 0700 "$host_remote_root" >/dev/null
run_transport "$scp_executable" -q -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$agent_source" "$ssh_target:$host_agent_path"
host_helper_path=$host_remote_root/transport-v2-runner-host.py
run_transport "$scp_executable" -q -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$host_helper_source" "$ssh_target:$host_helper_path"
run_transport "$scp_executable" -q -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$config" "$ssh_target:$host_config_path"
run_transport "$scp_executable" -q -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$request" "$ssh_target:$host_request_path"
if [[ $action == provision ]]; then
  host_proxy_path=$(dirname "$host_agent_path")/transport-v2-runner-proxy.py
  host_template_path=$(dirname "$host_agent_path")/flowersec-formal@.service
  run_transport "$scp_executable" -q -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$proxy_source" "$ssh_target:$host_proxy_path"
  run_transport "$scp_executable" -q -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$template_source" "$ssh_target:$host_template_path"
fi
if [[ $action == provision || $action == doctor ]]; then
  host_kvm_helper_path=$(dirname "$host_agent_path")/transport-v2-runner-kvm.py
  run_transport "$scp_executable" -q -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$kvm_helper_source" "$ssh_target:$host_kvm_helper_path"
fi
if [[ $action == provision ]]; then
  host_kvm_template_path=$(dirname "$host_agent_path")/flowersec-kvm-guest@.service
  run_transport "$scp_executable" -q -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$kvm_template_source" "$ssh_target:$host_kvm_template_path"
fi
if [[ $action == deploy ]]; then
  run_transport "$scp_executable" -q -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$bundle" "$ssh_target:$host_bundle_path"
fi

set +e
remote_result=$("$ssh_executable" -n -o ConnectTimeout=10 -o ConnectionAttempts=1 "$ssh_target" "$host_agent_path" --role host "$action" "$host_config_path" "$host_request_path" flowersec-remote-runner-v1)
remote_status=$?
set -e
if [[ $remote_status != 0 ]] && ! validate_remote_result "$remote_result"; then
  remote_result=$(reachability_failure)
  remote_status=20
fi
validate_remote_result "$remote_result" || { echo "remote runner returned an invalid closed-schema result" >&2; exit 4; }
if [[ $action == collect ]] && jq -e --arg sha "$source_sha" '
  .schema == "flowersec-remote-runner-result-v1" and .source_sha == $sha and (.status == "GREEN" or .status == "RED") and
  (.host_archive_path | type == "string" and length > 0) and (.archive_sha256 | test("^[0-9a-f]{64}$"))
' <<<"$remote_result" >/dev/null 2>&1; then
  host_archive_path=$(jq -er '.host_archive_path' <<<"$remote_result")
  archive_sha256=$(jq -er '.archive_sha256' <<<"$remote_result")
  collected_temp=$(mktemp "$(dirname "$output_path")/.transport-v2-collection.XXXXXX")
  chmod 0600 "$collected_temp"
  run_transport "$scp_executable" -q -o ConnectTimeout=10 -o ConnectionAttempts=1 -- "$ssh_target:$host_archive_path" "$collected_temp"
  [[ $(sha256_file "$collected_temp") == "$archive_sha256" ]] || {
    echo "collected closure digest mismatch" >&2
    exit 4
  }
  mv -- "$collected_temp" "$output_path"
  collected_temp=
  remote_result=$(jq -c --arg path "$output_path" '. + {local_archive_path:$path}' <<<"$remote_result")
fi
if [[ $remote_status != 0 ]]; then
  if jq -e --arg action "$action" --arg sha "$source_sha" '
    .schema == "flowersec-remote-runner-result-v1" and .status == "RED" and .action == $action and .source_sha == $sha
  ' <<<"$remote_result" >/dev/null 2>&1; then
    persist_failure "$remote_result" "$remote_status"
  fi
  exit "$remote_status"
fi
jq -e '.status == "GREEN" or .status == "RUNNING"' <<<"$remote_result" >/dev/null || {
  echo "remote runner returned a non-success result with status zero" >&2
  exit 4
}

write_state_atomically() {
  local temporary existing
  temporary=$(mktemp "$(dirname "$state_path")/.transport-v2-runner-state.XXXXXX.json")
  existing='{"schema":"flowersec-remote-runner-state-v1","actions":{}}'
  if [[ -f $state_path && ! -L $state_path ]]; then existing=$(<"$state_path"); fi
  jq -n \
    --argjson existing "$existing" \
    --argjson result "$remote_result" \
    --arg action "$action" \
    --arg config_sha256 "$config_sha256" \
    --arg updated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{schema:"flowersec-remote-runner-state-v1",config_sha256:$config_sha256,updated_at:$updated_at,
      actions:($existing.actions // {})} |
      if $action != "cleanup" then del(.actions.cleanup) else . end |
      .actions[$action]=$result' >"$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$state_path"
}

write_state_atomically
printf '%s\n' "$remote_result"
