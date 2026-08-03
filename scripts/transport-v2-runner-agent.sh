#!/usr/bin/env bash

set -euo pipefail
export PATH=${PATH:-}:/usr/local/go/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

usage() {
  echo "usage: transport-v2-runner-agent.sh --role <host|lxd|guest|guest-root> <action> <config> <request>" >&2
  exit 2
}

[[ $# == 6 && $1 == --role ]] || usage
role=$2
action=$3
config=$4
request=$5
[[ -n ${6:-} ]] || usage
# The sixth argument is a protocol sentinel. It prevents an older five-argument
# caller from silently executing a newer state transition.
[[ $6 == flowersec-remote-runner-v1 ]] || usage
case "$role" in host | lxd | guest | guest-root) ;; *) usage ;; esac
case "$action" in doctor | doctor-root | provision | deploy | run-formal | run-formal-root | collect | cleanup) ;; *) usage ;; esac
[[ -f $config && ! -L $config && -f $request && ! -L $request ]] || usage
if [[ $role == host ]]; then
  host_helper=$(dirname "${BASH_SOURCE[0]}")/transport-v2-runner-host.py
  [[ -f $host_helper && ! -L $host_helper ]] || usage
  exec /usr/bin/python3 "$host_helper" "$@"
fi

jq -e --arg action "$action" '
  .schema == "flowersec-remote-runner-request-v1" and
  (keys | sort) == (["action","agent_sha256","archive_sha256","base_sha","bundle_sha256","config_sha256",
    "host_bundle_path","host_helper_sha256","output_path","proxy_sha256","schema","source_sha","template_sha256"] | sort) and
  (.action == $action or ($action == "doctor-root" and .action == "doctor") or ($action == "run-formal-root" and .action == "run-formal")) and
  (.source_sha | test("^[0-9a-f]{40}$")) and
  (.base_sha == "" or (.base_sha | test("^[0-9a-f]{40}$"))) and
  (.agent_sha256 | test("^[0-9a-f]{64}$")) and
  (.host_helper_sha256 | test("^[0-9a-f]{64}$")) and
  (.proxy_sha256 | test("^[0-9a-f]{64}$")) and
  (.template_sha256 | test("^[0-9a-f]{64}$")) and
  (.archive_sha256 == "" or (.archive_sha256 | test("^[0-9a-f]{64}$")))
' "$request" >/dev/null || usage
jq -e '
  .schema == "flowersec-remote-runner-config-v1" and
  (keys | sort) == (["artifact_root","dependency_urls","guest_identity_file","guest_known_hosts_file","guest_port",
    "guest_repo","guest_root","guest_target","host_agent_path","host_config_path","host_request_path","lxc_name",
    "lxc_root","proxy_url","runner_id","schema","scp_executable","ssh_executable","ssh_target","state_path"] | sort)
' "$config" >/dev/null || usage
source_sha=$(jq -r '.source_sha' "$request")
base_sha=$(jq -r '.base_sha' "$request")
runner_id=$(jq -r '.runner_id' "$config")
lxc_name=$(jq -r '.lxc_name' "$config")
lxc_root=$(jq -r '.lxc_root' "$config")
guest_target=$(jq -r '.guest_target' "$config")
guest_port=$(jq -r '.guest_port' "$config")
guest_identity_file=$(jq -r '.guest_identity_file' "$config")
guest_known_hosts_file=$(jq -r '.guest_known_hosts_file' "$config")
guest_root=$(jq -r '.guest_root' "$config")
guest_repo=$(jq -r '.guest_repo' "$config")
guest_home=$(dirname "$guest_root")
artifact_root=$(jq -r '.artifact_root' "$config")
proxy_url=$(jq -r '.proxy_url' "$config")
host_agent_path=$(jq -r '.host_agent_path' "$config")
host_config_path=$(jq -r '.host_config_path' "$config")
host_request_path=$(jq -r '.host_request_path' "$config")

for value in "$runner_id" "$lxc_name" "$lxc_root" "$guest_target" "$guest_identity_file" "$guest_known_hosts_file" \
  "$guest_root" "$guest_repo" "$artifact_root" "$host_agent_path" "$host_config_path" "$host_request_path"; do
  [[ $value =~ ^[A-Za-z0-9_@./:-]+$ ]] || { echo "unsafe runner agent token" >&2; exit 2; }
done

result_json() {
  local status=$1 message=$2 check_id=${3:-} classification=${4:-none}
  jq -cn --arg schema flowersec-remote-runner-result-v1 --arg status "$status" --arg action "${action%-root}" \
    --arg source_sha "$source_sha" --arg base_sha "$base_sha" --arg message "$message" --arg check_id "$check_id" \
    --arg classification "$classification" \
    '{schema:$schema,status:$status,action:$action,source_sha:$source_sha,base_sha:$base_sha,
      classification:$classification,message:$message,check_id:$check_id}'
}

write_status_atomically() {
  local status_path=$1 payload=$2 temporary
  install -d -m 0700 "$(dirname "$status_path")"
  temporary=$(mktemp "$(dirname "$status_path")/.remote-runner-status.XXXXXX")
  printf '%s\n' "$payload" >"$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$status_path"
}

agent_fail() {
  local check_id=$1 message=$2 classification=$3 status_code=$4 payload
  payload=$(result_json RED "$message" "$check_id" "$classification")
  write_status_atomically "$request.status" "$payload"
  printf '%s\n' "$payload"
  exit "$status_code"
}

[[ $(sha256sum "$config" | awk '{print $1}') == "$(jq -r '.config_sha256' "$request")" ]] || \
  agent_fail runner_config_digest "runner config digest drifted" identity 30
[[ $(sha256sum "${BASH_SOURCE[0]}" | awk '{print $1}') == "$(jq -r '.agent_sha256' "$request")" ]] || \
  agent_fail runner_agent_digest "runner agent digest drifted" identity 30

validate_result() {
  local payload=$1 expected_action=${action%-root}
  validate_any_result "$payload"
  jq -e --arg action "$expected_action" --arg sha "$source_sha" '
    .schema == "flowersec-remote-runner-result-v1" and .action == $action and .source_sha == $sha and
    (.status == "GREEN" or .status == "RUNNING")
  ' <<<"$payload" >/dev/null
}

validate_any_result() {
  local payload=$1 expected_action=${action%-root}
  jq -e --arg action "$expected_action" --arg sha "$source_sha" --arg base "$base_sha" --arg role "$role" '
    .schema == "flowersec-remote-runner-result-v1" and .action == $action and .source_sha == $sha and
    .base_sha == $base and (.classification | type == "string") and (.check_id | type == "string") and
    (.message | type == "string") and (.status == "GREEN" or .status == "RUNNING" or .status == "RED") and
    if $action != "collect" or .status == "RUNNING" or (has("archive_path") | not) then
      (keys | sort) == (["action","base_sha","check_id","classification","message","schema","source_sha","status"] | sort)
    elif $role == "lxd" then
      (keys | sort) == (["action","archive_path","archive_sha256","base_sha","check_id","classification","message","schema","source_sha","status"] | sort)
    else
      (keys | sort) == (["action","archive_path","archive_sha256","base_sha","check_id","classification","lxd_archive_path","message","schema","source_sha","status"] | sort)
    end
  ' <<<"$payload" >/dev/null
}

ssh_executable=/usr/bin/ssh
scp_executable=/usr/bin/scp
guest_agent=$guest_root/transport-v2-runner-agent.sh
guest_config=$guest_root/runner-config.json
guest_request=$guest_root/request.json
lxd_agent=$lxc_root/transport-v2-runner-agent.sh
lxd_config=$lxc_root/runner-config.json
lxd_request=$lxc_root/request.json
lxd_bundle=$lxc_root/$source_sha.bundle
guest_bundle=$guest_root/$source_sha.bundle
short_sha=${source_sha:0:12}
unit=flowersec-formal@$short_sha-$runner_id.service
artifact_path=$artifact_root/formal-$source_sha-$runner_id
report_path=$artifact_path/report.unsigned.json
formal_lock=$artifact_root/.transport-v2-formal.lock
prepared_root=$guest_root/prepared/$source_sha
prepared_metadata=$prepared_root/metadata.json
prepared_runner=$prepared_root/transport-release-runner
prepared_transportcheck=$prepared_root/transportcheck
stable_agent=/usr/local/libexec/flowersec-transport-v2-runner-agent
stable_config=/etc/flowersec/transport-v2-runner.json
stable_request=/run/flowersec/transport-v2-runner-request.json
case "$action" in
  doctor) action_timeout=35s ;;
  provision) action_timeout=10m ;;
  deploy) action_timeout=20m ;;
  run-formal) action_timeout=1m ;;
  collect | cleanup) action_timeout=3m ;;
  *) action_timeout=30s ;;
esac


guest_ssh_args=(-T -i "$guest_identity_file" -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$guest_known_hosts_file" -o ConnectTimeout=10 -o ConnectionAttempts=1 -p "$guest_port" "$guest_target")
guest_scp_args=(-q -i "$guest_identity_file" -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$guest_known_hosts_file" -o ConnectTimeout=10 -o ConnectionAttempts=1 -P "$guest_port")

run_lxd() {
  local nested_result nested_status archive_path archive_sha lxd_archive lxd_archive_temp lxd_template guest_template candidate expected_archive
  chmod 0700 "$lxd_agent"
  chmod 0600 "$lxd_config" "$lxd_request"
  "$ssh_executable" -n "${guest_ssh_args[@]}" install -d -m 0700 "$guest_root"
  "$scp_executable" "${guest_scp_args[@]}" -- "$lxd_agent" "$guest_target:$guest_agent"
  "$scp_executable" "${guest_scp_args[@]}" -- "$lxd_config" "$guest_target:$guest_config"
  "$scp_executable" "${guest_scp_args[@]}" -- "$lxd_request" "$guest_target:$guest_request"
  [[ $("$ssh_executable" -n "${guest_ssh_args[@]}" sha256sum "$guest_agent" | awk '{print $1}') == "$(jq -r '.agent_sha256' "$request")" ]] || agent_fail guest_agent_digest "guest agent transfer digest drifted" identity 30
  [[ $("$ssh_executable" -n "${guest_ssh_args[@]}" sha256sum "$guest_config" | awk '{print $1}') == "$(jq -r '.config_sha256' "$request")" ]] || agent_fail guest_config_digest "guest config transfer digest drifted" identity 30
  if [[ $action == provision ]]; then
    lxd_template=$lxc_root/flowersec-formal@.service
    guest_template=$guest_root/flowersec-formal@.service
    [[ -f $lxd_template && ! -L $lxd_template ]]
    "$scp_executable" "${guest_scp_args[@]}" -- "$lxd_template" "$guest_target:$guest_template"
    [[ $("$ssh_executable" -n "${guest_ssh_args[@]}" sha256sum "$guest_template" | awk '{print $1}') == "$(jq -r '.template_sha256' "$request")" ]] || agent_fail guest_template_digest "guest template transfer digest drifted" identity 30
  fi
  if [[ $action == deploy ]]; then
    [[ -f $lxd_bundle && ! -L $lxd_bundle ]]
    [[ $(sha256sum "$lxd_bundle" | awk '{print $1}') == "$(jq -r '.bundle_sha256' "$request")" ]] || agent_fail lxd_bundle_digest "LXD deploy bundle digest drifted" identity 30
    "$scp_executable" "${guest_scp_args[@]}" -- "$lxd_bundle" "$guest_target:$guest_bundle"
  fi
  set +e
  nested_result=$(timeout --signal=TERM --kill-after=5s "$action_timeout" "$ssh_executable" -n "${guest_ssh_args[@]}" "$guest_agent" --role guest "$action" "$guest_config" "$guest_request" flowersec-remote-runner-v1)
  nested_status=$?
  set -e
  validate_any_result "$nested_result"
  if [[ $nested_status == 0 ]]; then validate_result "$nested_result"; fi
  if [[ $action == deploy ]]; then rm -f -- "$lxd_bundle"; fi
  if [[ $action == collect && ($(jq -r '.status' <<<"$nested_result") == GREEN || $(jq -r '.status' <<<"$nested_result") == RED) ]]; then
    archive_path=$(jq -er '.archive_path' <<<"$nested_result")
    archive_sha=$(jq -er '.archive_sha256' <<<"$nested_result")
    lxd_archive=$lxc_root/$(basename "$archive_path")
    if [[ ! -e $lxd_archive && ! -L $lxd_archive ]]; then
      lxd_archive_temp=$(mktemp "$lxc_root/.collect-$source_sha.XXXXXX")
      if ! timeout --signal=TERM --kill-after=5s 5m "$scp_executable" "${guest_scp_args[@]}" -- "$guest_target:$archive_path" "$lxd_archive_temp"; then
        rm -f -- "$lxd_archive_temp"
        exit 20
      fi
      [[ $(sha256sum "$lxd_archive_temp" | awk '{print $1}') == "$archive_sha" ]] || agent_fail lxd_archive_digest "LXD collection transfer digest drifted" identity 30
      mv -- "$lxd_archive_temp" "$lxd_archive"
    fi
    [[ $(sha256sum "$lxd_archive" | awk '{print $1}') == "$archive_sha" ]] || agent_fail lxd_archive_digest "LXD collection archive digest drifted" identity 30
    nested_result=$(jq -c --arg path "$lxd_archive" '. + {lxd_archive_path:$path}' <<<"$nested_result")
  fi
  if [[ $action == cleanup ]]; then
    expected_archive=$(jq -r '.archive_sha256' "$request")
    if [[ -n $expected_archive ]]; then
      for candidate in "$lxc_root/$source_sha-$runner_id-formal-closure.tar.gz" "$lxc_root/$source_sha-$runner_id-formal-failure.tar.gz"; do
        if [[ -e $candidate || -L $candidate ]]; then
          [[ -f $candidate && ! -L $candidate && $(sha256sum "$candidate" | awk '{print $1}') == "$expected_archive" ]] || agent_fail lxd_cleanup_digest "LXD cleanup archive digest drifted" cleanup 40
          rm -- "$candidate"
        fi
      done
    fi
    if [[ -e $lxd_bundle || -L $lxd_bundle ]]; then
      [[ -f $lxd_bundle && ! -L $lxd_bundle ]] || agent_fail lxd_cleanup_bundle "LXD deploy bundle is not a regular task file" cleanup 40
      rm -- "$lxd_bundle"
    fi
    find "$lxc_root" -maxdepth 1 -type f -name ".collect-$source_sha.*" -delete
  fi
  write_status_atomically "$lxd_request.status" "$nested_result"
  printf '%s\n' "$nested_result"
  if [[ $action == cleanup && $nested_status == 0 ]]; then
    rm -f -- "$lxd_agent" "$lxd_config" "$lxd_request" "$lxd_request.status" "$lxc_root/flowersec-formal@.service"
  fi
  if [[ $nested_status != 0 ]]; then exit "$nested_status"; fi
}

guest_result() {
  local payload=$1
  write_status_atomically "$guest_request.status" "$payload"
  printf '%s\n' "$payload"
}

run_guest_deploy() {
  local expected identity build_temp toolchain_material toolchain_sha dist_sha runner_sha transportcheck_sha metadata_revision metadata_modified
  expected=$(jq -r '.bundle_sha256' "$request")
  [[ -f $guest_bundle && ! -L $guest_bundle ]]
  [[ $(sha256sum "$guest_bundle" | awk '{print $1}') == "$expected" ]] || agent_fail guest_bundle_digest "guest deploy bundle digest drifted" identity 30
  git -C "$guest_repo" diff --quiet
  test -z "$(git -C "$guest_repo" status --porcelain --untracked-files=all)"
  git -C "$guest_repo" bundle verify "$guest_bundle" >/dev/null
  git -C "$guest_repo" fetch --no-tags "$guest_bundle" "$source_sha"
  git -C "$guest_repo" checkout --quiet --detach "$source_sha"
  [[ $(git -C "$guest_repo" rev-parse HEAD) == "$source_sha" ]]
  test -z "$(git -C "$guest_repo" status --porcelain --untracked-files=all)"
  export PATH=/usr/local/go/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  export GOOS=linux CGO_ENABLED=0 GOWORK=off GOFLAGS=-mod=readonly GOPROXY=off
  case $(uname -m) in x86_64) export GOARCH=amd64 ;; aarch64) export GOARCH=arm64 ;; *) exit 3 ;; esac
  install -d -m 0700 "$(dirname "$prepared_root")"
  find "$guest_root" -maxdepth 1 -type d -name ".prepared-$source_sha.*" -exec rm -rf -- {} +
  if [[ -e $prepared_root || -L $prepared_root ]]; then
    [[ -d $prepared_root && ! -L $prepared_root && -f $prepared_metadata && ! -L $prepared_metadata ]]
    jq -e --arg sha "$source_sha" '
      .schema == "flowersec-prepared-runner-v1" and .source_sha == $sha and
      (.runner_sha256 | test("^[0-9a-f]{64}$")) and (.transportcheck_sha256 | test("^[0-9a-f]{64}$")) and
      (.toolchain_sha256 | test("^[0-9a-f]{64}$")) and (.dist_sha256 | test("^[0-9a-f]{64}$"))
    ' "$prepared_metadata" >/dev/null
    [[ $(sha256sum "$prepared_runner" | awk '{print $1}') == "$(jq -r '.runner_sha256' "$prepared_metadata")" ]] || agent_fail prepared_runner_digest "prepared runner digest drifted" identity 30
    [[ $(sha256sum "$prepared_transportcheck" | awk '{print $1}') == "$(jq -r '.transportcheck_sha256' "$prepared_metadata")" ]] || agent_fail prepared_transportcheck_digest "prepared transportcheck digest drifted" identity 30
  else
    build_temp=$(mktemp -d "$guest_root/.prepared-$source_sha.XXXXXX")
    trap 'rm -rf -- "$build_temp"' EXIT HUP INT TERM
    (
      cd "$guest_repo/flowersec-ts"
      npm run build
    )
    (
      cd "$guest_repo/flowersec-go"
      go build -trimpath -buildvcs=false -o "$build_temp/transport-release-runner" ./internal/cmd/transport-release-runner
    )
    (
      cd "$guest_repo/tools/transportcheck"
      go build -trimpath -buildvcs=true -o "$build_temp/transportcheck" .
    )
    metadata_revision=$(go version -m "$build_temp/transportcheck" | sed -n 's/^[[:space:]]*build[[:space:]]*vcs\.revision=//p')
    metadata_modified=$(go version -m "$build_temp/transportcheck" | sed -n 's/^[[:space:]]*build[[:space:]]*vcs\.modified=//p')
    [[ $metadata_revision == "$source_sha" && $metadata_modified == false ]]
    runner_sha=$(sha256sum "$build_temp/transport-release-runner" | awk '{print $1}')
    transportcheck_sha=$(sha256sum "$build_temp/transportcheck" | awk '{print $1}')
    toolchain_material=$(cd "$guest_repo" && printf '%s\n' \
      "$(go version)" \
      "$(go env GOOS GOARCH CGO_ENABLED)" \
      "$(sha256sum flowersec-go/go.mod flowersec-go/go.sum flowersec-ts/package-lock.json)")
    toolchain_sha=$(printf '%s' "$toolchain_material" | sha256sum | awk '{print $1}')
    dist_sha=$(cd "$guest_repo/flowersec-ts" && find dist -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
    jq -n --arg schema flowersec-prepared-runner-v1 --arg source_sha "$source_sha" \
      --arg runner_sha256 "$runner_sha" --arg transportcheck_sha256 "$transportcheck_sha" \
      --arg toolchain_sha256 "$toolchain_sha" --arg dist_sha256 "$dist_sha" \
      '{schema:$schema,source_sha:$source_sha,runner_sha256:$runner_sha256,
        transportcheck_sha256:$transportcheck_sha256,toolchain_sha256:$toolchain_sha256,dist_sha256:$dist_sha256}' \
      >"$build_temp/metadata.json"
    chmod 0500 "$build_temp/transport-release-runner" "$build_temp/transportcheck"
    chmod 0600 "$build_temp/metadata.json"
    mv -- "$build_temp" "$prepared_root"
    build_temp=
    trap - EXIT HUP INT TERM
  fi
  identity=$guest_repo/.flowersec/transport-runner.json
  if [[ -e $identity || -L $identity ]]; then
    [[ -f $identity && ! -L $identity && $(stat -c %a "$identity") == 600 ]]
    rm -- "$identity"
  fi
  make -C "$guest_repo" transport-runner-config
  [[ -f $identity && ! -L $identity && $(stat -c %a "$identity") == 600 ]]
  rm -- "$guest_bundle"
  test -z "$(git -C "$guest_repo" status --porcelain --untracked-files=all)"
  guest_result "$(result_json GREEN "exact SHA deployed; prepared runner reused or built and identity regenerated")"
}

doctor_fail() {
  local check_id=$1 message=$2 classification=${3:-environment} status_code=20 payload
  case "$classification" in
    input) status_code=10 ;;
    environment | unreachable) status_code=20 ;;
    identity | policy) status_code=30 ;;
    residual | cleanup) status_code=40 ;;
  esac
  payload=$(result_json RED "$message" "$check_id" "$classification")
  write_status_atomically "$guest_request.status" "$payload"
  printf '%s\n' "$payload"
  exit "$status_code"
}

run_guest_doctor_root() {
  local preflight_root preflight_report runner_sha toolchain_sha dist_sha preflight_status preflight_check preflight_message preflight_classification formal_lock_owner urls metadata_revision metadata_modified
  local -a dependency_args=()
  [[ $(id -u) == 0 ]] || doctor_fail workload_context "doctor is not running as root"
  [[ ${FLOWERSEC_RUNNER_CONTEXT:-} == formal && ${FLOWERSEC_RUNNER_CONTEXT_SHA:-} == "$source_sha" ]] || doctor_fail workload_context "formal systemd context is not exact"
  [[ -x $prepared_runner && ! -L $prepared_runner && -x $prepared_transportcheck && ! -L $prepared_transportcheck && -f $prepared_metadata && ! -L $prepared_metadata ]] || doctor_fail prepared_runner "exact-SHA prepared runner is unavailable" identity
  jq -e --arg sha "$source_sha" '.schema == "flowersec-prepared-runner-v1" and .source_sha == $sha' "$prepared_metadata" >/dev/null || doctor_fail prepared_runner "prepared runner metadata drifted" identity
  runner_sha=$(jq -r '.runner_sha256' "$prepared_metadata")
  toolchain_sha=$(jq -r '.toolchain_sha256' "$prepared_metadata")
  dist_sha=$(jq -r '.dist_sha256' "$prepared_metadata")
  [[ $(sha256sum "$prepared_runner" | awk '{print $1}') == "$runner_sha" ]] || doctor_fail prepared_runner "prepared runner digest drifted" identity
  [[ $(sha256sum "$prepared_transportcheck" | awk '{print $1}') == "$(jq -r '.transportcheck_sha256' "$prepared_metadata")" ]] || doctor_fail prepared_runner "prepared transportcheck digest drifted" identity
  metadata_revision=$(go version -m "$prepared_transportcheck" | sed -n 's/^[[:space:]]*build[[:space:]]*vcs\.revision=//p')
  metadata_modified=$(go version -m "$prepared_transportcheck" | sed -n 's/^[[:space:]]*build[[:space:]]*vcs\.modified=//p')
  [[ $metadata_revision == "$source_sha" && $metadata_modified == false ]] || doctor_fail prepared_runner "prepared transportcheck VCS identity drifted" identity
  preflight_root=$guest_root/preflight
  install -d -m 0700 "$preflight_root"
  preflight_report=$preflight_root/$source_sha-formal.json
  [[ ! -L $preflight_report ]] || doctor_fail preflight_output "preflight report path is a symlink" input
  formal_lock_owner=formal-$source_sha
  exec 9>"$formal_lock"
  flock -n 9 || doctor_fail unique_job_lock "another formal job owns the runner" residual
  printf '%s\n' "$formal_lock_owner" >"$formal_lock"
  chmod 0600 "$formal_lock"
  trap 'if [[ -f $formal_lock && ! -L $formal_lock && $(<"$formal_lock") == "$formal_lock_owner" ]]; then rm -f -- "$formal_lock"; fi' EXIT HUP INT TERM
  while IFS= read -r urls; do dependency_args+=(-dependency-url "$urls"); done < <(jq -r '.dependency_urls[]' "$config")
  set +e
  FLOWERSEC_RUNNER_LOCK_OWNER="$formal_lock_owner" FLOWERSEC_RUNNER_LAUNCHER_VERIFIED=1 \
  FLOWERSEC_RUNNER_REACHABILITY_VERIFIED=1 FLOWERSEC_RUNNER_LAUNCHER_RUNTIME=lxc \
  HTTP_PROXY="$proxy_url" HTTPS_PROXY="$proxy_url" http_proxy="$proxy_url" https_proxy="$proxy_url" \
  ALL_PROXY= all_proxy= NO_PROXY= no_proxy= \
  timeout --signal=TERM --kill-after=1s 30s "$prepared_transportcheck" runner-preflight \
    -mode formal -repo "$guest_repo" -sha "$source_sha" -base-sha "$base_sha" \
    -runner-config "$guest_repo/.flowersec/transport-runner.json" -output "$preflight_report" \
    -artifact-path "$artifact_path" -runner-executable "$prepared_runner" -runner-sha256 "$runner_sha" \
    -host-bpftool /opt/host-linux-tools/bpftool -toolchain-sha256 "$toolchain_sha" -dist-sha256 "$dist_sha" \
    -lock-path "$formal_lock" -lock-owner "$formal_lock_owner" -cgroup-root /sys/fs/cgroup "${dependency_args[@]}"
  preflight_status=$?
  set -e
  if [[ $preflight_status != 0 ]]; then
    [[ -f $preflight_report && ! -L $preflight_report ]] || doctor_fail preflight_collection "unified preflight did not write a report"
    preflight_check=$(jq -r '.check_id // "preflight_collection"' "$preflight_report")
    preflight_message=$(jq -r '.message // "unified preflight failed"' "$preflight_report")
    preflight_classification=$(jq -r '.classification // "environment"' "$preflight_report")
    doctor_fail "$preflight_check" "$preflight_message" "$preflight_classification"
  fi
  jq -e --arg sha "$source_sha" --arg base "$base_sha" '
    .schema == "flowersec-runner-preflight-v1" and .status == "GREEN" and .classification == "none" and
    .mode == "formal" and .source_sha == $sha and .base_sha == $base and .workload_started == false and
    .check_id == "" and .message == "" and (.checks | length > 0 and all(.status == "GREEN"))
  ' "$preflight_report" >/dev/null || doctor_fail preflight_schema "unified preflight report is not strict GREEN" identity
  rm -f -- "$formal_lock"
  trap - EXIT HUP INT TERM
  guest_result "$(result_json GREEN "unified preflight passed in exact root systemd context")"
}

run_guest_doctor() {
  local doctor_unit nested_result nested_status
  doctor_unit=flowersec-doctor-$short_sha-$runner_id.service
  sudo -n systemctl reset-failed "$doctor_unit" >/dev/null 2>&1 || true
  set +e
  nested_result=$(sudo -n systemd-run --quiet --wait --pipe --collect --unit="$doctor_unit" \
    --property=Type=exec --property=RuntimeMaxSec=30s --property=TimeoutStopSec=2s --property=KillMode=control-group \
    --setenv=PATH=/usr/local/go/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --setenv=HOME=/root --setenv=RUSTUP_HOME=/usr/local/rustup --setenv=CARGO_HOME=/usr/local/cargo \
    --setenv=FLOWERSEC_RUNNER_CONTEXT=formal --setenv=FLOWERSEC_RUNNER_CONTEXT_SHA="$source_sha" \
    "$guest_agent" --role guest-root doctor-root "$guest_config" "$guest_request" flowersec-remote-runner-v1)
  nested_status=$?
  set -e
  if [[ $nested_status != 0 ]]; then
    validate_any_result "$nested_result"
    guest_result "$nested_result"
    exit "$nested_status"
  fi
  validate_result "$nested_result"
  guest_result "$nested_result"
}

run_guest_provision() {
  local guest_template
  guest_template=$guest_root/flowersec-formal@.service
  [[ -f $guest_template && ! -L $guest_template ]]
  [[ $(sha256sum "$guest_template" | awk '{print $1}') == "$(jq -r '.template_sha256' "$request")" ]] || agent_fail guest_template_digest "guest template digest drifted" identity 30
  sudo -n install -d -m 0755 /usr/local/libexec /etc/flowersec
  sudo -n install -m 0555 "$guest_agent" "$stable_agent"
  sudo -n install -m 0600 "$guest_config" "$stable_config"
  sudo -n install -m 0644 "$guest_template" /etc/systemd/system/flowersec-formal@.service
  [[ $(sudo -n sha256sum "$stable_agent" | awk '{print $1}') == "$(jq -r '.agent_sha256' "$request")" ]] || agent_fail stable_agent_digest "installed formal agent digest drifted" identity 30
  [[ $(sudo -n sha256sum "$stable_config" | awk '{print $1}') == "$(jq -r '.config_sha256' "$request")" ]] || agent_fail stable_config_digest "installed formal config digest drifted" identity 30
  sudo -n systemctl daemon-reload
  sudo -n git config --global --replace-all safe.directory "$guest_repo"
  for tool in go node jq flock timeout tini ip nft tc bpftool clang rustup cargo curl docker; do command -v "$tool" >/dev/null; done
  sudo -n timeout --signal=TERM --kill-after=1s 10s docker info --format '{{.ServerVersion}}' >/dev/null
  (cd "$guest_repo/flowersec-rust" && CARGO_NET_OFFLINE=true rustup run 1.88.0 cargo metadata --locked --offline --format-version 1 >/dev/null)
  find "$guest_home/.cache/ms-playwright" -type f -name chrome -perm -111 -print -quit | grep -q .
  guest_result "$(result_json GREEN "stable toolchain, cache, Chromium, permissions, and proxy prerequisites are provisioned")"
}

run_guest_formal() {
  local invocation_id
  invocation_id=$(sudo -n systemctl show "$unit" -p InvocationID --value 2>/dev/null || true)
  if [[ -n $invocation_id ]]; then
    sudo -n jq -e --arg sha "$source_sha" --arg config_sha "$(jq -r '.config_sha256' "$request")" '
      .schema == "flowersec-remote-runner-request-v1" and .action == "run-formal" and
      .source_sha == $sha and .config_sha256 == $config_sha
    ' "$stable_request" >/dev/null || doctor_fail formal_recovery "existing formal unit is not bound to the exact request" residual
    guest_result "$(result_json RUNNING "recovered the existing exact-SHA supervised formal collector")"
    return
  fi
  [[ ! -e $artifact_path && ! -L $artifact_path ]]
  [[ ! -e $formal_lock && ! -L $formal_lock ]]
  sudo -n install -d -m 0755 /run/flowersec
  sudo -n install -m 0600 "$guest_request" "$stable_request"
  [[ $(sudo -n sha256sum "$stable_agent" | awk '{print $1}') == "$(jq -r '.agent_sha256' "$request")" ]] || agent_fail stable_agent_digest "installed formal agent digest drifted" identity 30
  [[ $(sudo -n sha256sum "$stable_config" | awk '{print $1}') == "$(jq -r '.config_sha256' "$request")" ]] || agent_fail stable_config_digest "installed formal config digest drifted" identity 30
  sudo -n systemctl start "$unit"
  guest_result "$(result_json RUNNING "unique supervised formal collector started")"
}

run_guest_formal_root() {
  local urls release_owner_uid release_owner_gid
  [[ $(id -u) == 0 ]]
  [[ $(git -c safe.directory="$guest_repo" -C "$guest_repo" rev-parse HEAD) == "$source_sha" ]]
  test -z "$(git -c safe.directory="$guest_repo" -C "$guest_repo" status --porcelain --untracked-files=all)"
  urls=$(jq -r '.dependency_urls | join(" ")' "$config")
  release_owner_uid=$(stat -c %u "$guest_repo")
  release_owner_gid=$(stat -c %g "$guest_repo")
  export PATH=/usr/local/go/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  export HOME=/root RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo CARGO_NET_OFFLINE=true
  export GOWORK=off GOFLAGS=-mod=readonly GOPROXY=off GOMODCACHE=$guest_home/go/pkg/mod
  export PLAYWRIGHT_BROWSERS_PATH=$guest_home/.cache/ms-playwright
  export FLOWERSEC_RUNNER_REACHABILITY_VERIFIED=1 FLOWERSEC_RUNNER_LAUNCHER_RUNTIME=lxc
  export FLOWERSEC_TRANSPORT_RUNNER_CONFIG=$guest_repo/.flowersec/transport-runner.json
  export FLOWERSEC_RELEASE_PREFLIGHT_PROXY=$proxy_url FLOWERSEC_RELEASE_PREFLIGHT_URLS=$urls
  export FLOWERSEC_RELEASE_OWNER_UID=$release_owner_uid FLOWERSEC_RELEASE_OWNER_GID=$release_owner_gid TRANSPORT_V2_BASE_SHA=$base_sha
  export FLOWERSEC_RELEASE_PREPARED_ROOT=$prepared_root
  exec "$guest_repo/scripts/transport-v2-release-runner.sh" --target all --report "$report_path"
}

run_guest_collect() {
  local active result archive archive_sha payload journal
  local -a failure_members=()
  active=$(sudo -n systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  result=$(sudo -n systemctl show "$unit" -p Result --value 2>/dev/null || true)
  if [[ $active == active || $active == activating ]]; then
    guest_result "$(result_json RUNNING "formal collector is still running")"
    return
  fi
  if [[ $result != success ]]; then
    journal=$guest_root/$source_sha-$runner_id-formal-journal.log
    archive=$artifact_root/$source_sha-$runner_id-formal-failure.tar.gz
    [[ ! -L $journal && ! -L $archive ]]
    sudo -n journalctl --no-pager -u "$unit" >"$journal"
    failure_members+=(-C "$guest_root" "$(basename "$journal")")
    if [[ -d $artifact_path && ! -L $artifact_path ]]; then failure_members+=(-C "$artifact_root" "$(basename "$artifact_path")"); fi
    sudo -n tar -czf "$archive" "${failure_members[@]}"
    sudo -n chown "$(id -u):$(id -g)" "$archive" "$journal"
    archive_sha=$(sha256sum "$archive" | awk '{print $1}')
    payload=$(result_json RED "formal collector failed" formal_collector)
    payload=$(jq -c --arg path "$archive" --arg sha "$archive_sha" '. + {archive_path:$path,archive_sha256:$sha}' <<<"$payload")
    write_status_atomically "$guest_request.status" "$payload"
    printf '%s\n' "$payload"
    exit 20
  fi
  [[ -f $report_path && ! -L $report_path ]]
  archive=$artifact_root/$source_sha-$runner_id-formal-closure.tar.gz
  [[ ! -L $archive ]]
  sudo -n tar -C "$artifact_root" -czf "$archive" "$(basename "$artifact_path")"
  sudo -n chown "$(id -u):$(id -g)" "$archive"
  archive_sha=$(sha256sum "$archive" | awk '{print $1}')
  payload=$(result_json GREEN "formal evidence closure is ready")
  payload=$(jq -c --arg path "$archive" --arg sha "$archive_sha" '. + {archive_path:$path,archive_sha256:$sha}' <<<"$payload")
  guest_result "$payload"
}

run_guest_cleanup() {
  local lock_owner expected_archive candidate archive_found=0 identity preflight_report
  expected_archive=$(jq -r '.archive_sha256' "$request")
  timeout --signal=TERM --kill-after=2s 35s sudo -n systemctl stop "$unit" >/dev/null 2>&1 || true
  sudo -n systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  if [[ -f $formal_lock && ! -L $formal_lock ]]; then
    lock_owner=$(sudo -n cat "$formal_lock")
    [[ $lock_owner == formal-$source_sha ]]
    sudo -n rm -- "$formal_lock"
  fi
  rm -f -- "$guest_bundle"
  for candidate in "$artifact_root/$source_sha-$runner_id-formal-closure.tar.gz" "$artifact_root/$source_sha-$runner_id-formal-failure.tar.gz"; do
    if [[ -e $candidate || -L $candidate ]]; then
      [[ -n $expected_archive ]] || doctor_fail artifact_ownership "remote formal artifact has no checksummed local receipt" cleanup
      [[ -f $candidate && ! -L $candidate && $(sha256sum "$candidate" | awk '{print $1}') == "$expected_archive" ]] || doctor_fail artifact_digest "remote formal archive digest does not match the local receipt" cleanup
      archive_found=$((archive_found + 1))
      rm -- "$candidate"
    fi
  done
  [[ $archive_found -le 1 ]] || doctor_fail artifact_ownership "multiple remote formal archives exist" cleanup
  if [[ -e $artifact_path || -L $artifact_path ]]; then
    [[ -n $expected_archive && -d $artifact_path && ! -L $artifact_path && $archive_found == 1 ]] || doctor_fail artifact_ownership "formal artifact cannot be deleted without its verified archive" cleanup
    sudo -n rm -rf -- "$artifact_path"
  fi
  rm -f -- "$guest_root/$source_sha-$runner_id-formal-journal.log"
  if [[ -e $prepared_root || -L $prepared_root ]]; then
    [[ -d $prepared_root && ! -L $prepared_root && -f $prepared_metadata && ! -L $prepared_metadata ]]
    jq -e --arg sha "$source_sha" '.schema == "flowersec-prepared-runner-v1" and .source_sha == $sha' "$prepared_metadata" >/dev/null
    [[ $(sha256sum "$prepared_runner" | awk '{print $1}') == "$(jq -r '.runner_sha256' "$prepared_metadata")" ]] || doctor_fail prepared_runner_digest "prepared runner digest blocks cleanup" cleanup
    [[ $(sha256sum "$prepared_transportcheck" | awk '{print $1}') == "$(jq -r '.transportcheck_sha256' "$prepared_metadata")" ]] || doctor_fail prepared_transportcheck_digest "prepared transportcheck digest blocks cleanup" cleanup
    rm -rf -- "$prepared_root"
  fi
  find "$guest_root" -maxdepth 1 -type d -name ".prepared-$source_sha.*" -exec rm -rf -- {} +
  preflight_report=$guest_root/preflight/$source_sha-formal.json
  if [[ -e $preflight_report || -L $preflight_report ]]; then
    [[ -f $preflight_report && ! -L $preflight_report ]]
    rm -- "$preflight_report"
    rmdir "$guest_root/preflight" 2>/dev/null || true
  fi
  identity=$guest_repo/.flowersec/transport-runner.json
  if [[ -e $identity || -L $identity ]]; then
    [[ -f $identity && ! -L $identity && $(stat -c %a "$identity") == 600 ]]
    rm -- "$identity"
  fi
  sudo -n rm -f -- "$stable_request"
  ! pgrep -f 'transport-release-runner|transportcheck collect|chromium.*flowersec' >/dev/null
  ! sudo -n ip netns list | grep -qi flowersec
  [[ -z $(sudo -n find /sys/fs/cgroup -mindepth 1 -maxdepth 8 -type d \( -iname '*transportcheck*' -o -iname '*flowersec-fc-*' \) -print -quit 2>/dev/null) ]]
  [[ -z $(sudo -n find /sys/fs/bpf -mindepth 1 -maxdepth 8 \( -iname '*transportcheck*' -o -iname '*flowersec*' \) -print -quit 2>/dev/null) ]]
  guest_result "$(result_json GREEN "verified exact-SHA artifacts and workload residuals are clean")"
  rm -f -- "$guest_agent" "$guest_config" "$guest_request" "$guest_request.status" "$guest_root/flowersec-formal@.service"
}

case "$role:$action" in
  lxd:*) run_lxd ;;
  guest:deploy) run_guest_deploy ;;
  guest:doctor) run_guest_doctor ;;
  guest:provision) run_guest_provision ;;
  guest:run-formal) run_guest_formal ;;
  guest-root:run-formal-root) run_guest_formal_root ;;
  guest:collect) run_guest_collect ;;
  guest:cleanup) run_guest_cleanup ;;
  guest-root:doctor-root) run_guest_doctor_root ;;
  *) usage ;;
esac
