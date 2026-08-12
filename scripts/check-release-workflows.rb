#!/usr/bin/env ruby

require "psych"
require "digest"

class PolicyError < StandardError; end

def require_condition(condition, message)
  raise PolicyError, message unless condition
end

def implicit_non_string_yaml_key?(key)
  return false unless key.plain
  !Psych.safe_load(key.value, aliases: false).is_a?(String)
rescue Psych::Exception
  true
end

def canonical_plain_yaml_scalar?(node)
  return true unless node.plain
  decoded = Psych.safe_load(node.value, aliases: false)
  case decoded
  when String
    true
  when TrueClass
    node.value == "true"
  when FalseClass
    node.value == "false"
  when Integer
    node.value == decoded.to_s
  else
    false
  end
rescue Psych::Exception
  false
end

def validate_yaml_node(node, path, root: false, allow_actions_on: false)
  if node.respond_to?(:anchor) && node.anchor && !node.anchor.empty?
    raise PolicyError, "#{path} must not use YAML anchors"
  end
  if node.respond_to?(:tag) && node.tag && !node.tag.empty?
    raise PolicyError, "#{path} must not use explicit YAML tags"
  end

  case node
  when Psych::Nodes::Alias
    raise PolicyError, "#{path} must not use YAML aliases or merge keys"
  when Psych::Nodes::Mapping
    seen = {}
    node.children.each_slice(2) do |key, value|
      require_condition(key.is_a?(Psych::Nodes::Scalar), "#{path} must use scalar YAML mapping keys")
      decoded_key = key.value
      require_condition(decoded_key != "<<", "#{path} must not use YAML merge keys")
      if implicit_non_string_yaml_key?(key) && !(root && decoded_key == "on")
        raise PolicyError, "#{path} contains an ambiguous implicit YAML mapping key #{decoded_key.inspect}"
      end
      require_condition(!seen.key?(decoded_key), "#{path} contains duplicate YAML key #{decoded_key.inspect}")
      seen[decoded_key] = true
      validate_yaml_node(key, "#{path}.<key>", allow_actions_on: root && decoded_key == "on")
      validate_yaml_node(value, "#{path}.#{decoded_key}")
    end
  when Psych::Nodes::Sequence
    node.children.each_with_index do |child, index|
      validate_yaml_node(child, "#{path}[#{index}]")
    end
  when Psych::Nodes::Scalar
    canonical = canonical_plain_yaml_scalar?(node)
    canonical ||= allow_actions_on && node.plain && node.value == "on"
    require_condition(canonical, "#{path} must use a canonical YAML scalar spelling")
  end
end

def load_workflow(path)
  source = File.read(path)
  stream = Psych.parse_stream(source, filename: path)
  require_condition(stream.children.length == 1, "#{path} must contain exactly one YAML document")
  document = stream.children.first
  require_condition(document.root, "#{path} must not be empty")
  validate_yaml_node(document.root, path, root: true)
  workflow = Psych.safe_load(source, aliases: false, filename: path)
  require_condition(workflow.is_a?(Hash), "#{path} must contain a YAML mapping")
  workflow
rescue Psych::Exception => error
  raise PolicyError, "#{path} is not valid unambiguous YAML: #{error.message}"
end

def require_hash(value, context)
  require_condition(value.is_a?(Hash), "#{context} must be a mapping")
  value
end

def require_exact_keys(mapping, expected, context)
  actual = mapping.keys.sort_by(&:to_s)
  wanted = expected.sort_by(&:to_s)
  require_condition(actual == wanted, "#{context} fields must be exactly #{wanted.map(&:inspect).join(', ')}; got #{actual.map(&:inspect).join(', ')}")
end

def require_exact_value(actual, expected, context)
  require_condition(actual == expected, "#{context} must match the reviewed value")
end

def validate_step_contracts(steps, contracts, context)
  require_condition(steps.length == contracts.length, "#{context} step sequence must contain exactly #{contracts.length} reviewed steps")
  steps.zip(contracts).each_with_index do |(step, contract), index|
    step_context = "#{context} step #{index + 1} #{contract[:name].inspect}"
    require_condition(step["name"] == contract[:name], "#{context} step sequence changed at position #{index + 1}")
    require_exact_keys(step, contract.fetch(:keys), step_context)
    contract.fetch(:values, {}).each do |field, expected|
      require_exact_value(step[field], expected, "#{step_context} #{field}")
    end
    if contract[:run_sha256]
      require_condition(step["run"].is_a?(String), "#{step_context} must define a direct run command")
      actual_digest = Digest::SHA256.hexdigest(step["run"])
      require_condition(actual_digest == contract[:run_sha256], "#{step_context} run command must match the reviewed command")
    end
  end
end

def reject_publication_before(steps, boundary, context)
  run_patterns = [
    /\b(?:npm|pnpm|yarn)\s+publish\b/i,
    /\bcargo\s+publish\b/i,
    /\bgh\s+release\s+create\b/i,
    /\bdocker(?:\s+\S+)*\s+push\b/i,
    /\bgit\s+push\b/i,
  ]
  uses_pattern = /(?:publish|release|docker\/build-push-action)/i
  steps.each_with_index do |step, index|
    next unless index < boundary
    publication_run = step["run"].is_a?(String) && run_patterns.any? { |pattern| pattern.match?(step["run"]) }
    publication_action = step["uses"].is_a?(String) && uses_pattern.match?(step["uses"])
    require_condition(!publication_run && !publication_action, "#{context} contains publication-capable work before its validation gate")
  end
end

def require_job(workflow, job_name, context)
  jobs = require_hash(workflow["jobs"], "#{context} jobs")
  require_hash(jobs[job_name], "#{context} job #{job_name}")
end

def require_steps(job, context)
  steps = job["steps"]
  require_condition(steps.is_a?(Array), "#{context} must define a steps array")
  steps.each_with_index do |step, index|
    require_hash(step, "#{context} step #{index}")
  end
  steps
end

def require_named_step(steps, name, context)
  matches = steps.each_index.select { |index| steps[index]["name"] == name }
  require_condition(matches.length == 1, "#{context} must contain exactly one #{name.inspect} step")
  index = matches.first
  [steps[index], index]
end

def require_unconditional(mapping, context)
  require_condition(!mapping.key?("if"), "#{context} must remain unconditional")
  require_condition(!mapping.key?("continue-on-error"), "#{context} must not continue on error")
end

def require_condition_value(mapping, expected, context)
  require_condition(mapping["if"] == expected, "#{context} must use only the approved condition")
  require_condition(!mapping.key?("continue-on-error"), "#{context} must not continue on error")
end

def require_step_field(step, field, expected, context)
  require_condition(step[field] == expected, "#{context} must set #{field} as a direct step field")
end

begin
dependabot = load_workflow(".github/dependabot.yml")
release_workflow = load_workflow(".github/workflows/release.yml")
rust_workflow = load_workflow(".github/workflows/rust-release.yml")
ci_workflow = load_workflow(".github/workflows/ci.yml")
codeql_workflow = load_workflow(".github/workflows/codeql.yml")
scorecard_workflow = load_workflow(".github/workflows/scorecard.yml")

require_exact_keys(dependabot, ["version", "updates"], "Dependabot configuration")
require_exact_value(dependabot, {
  "version" => 2,
  "updates" => [{
    "package-ecosystem" => "github-actions",
    "directory" => "/",
    "schedule" => { "interval" => "weekly" },
    "groups" => {
      "codeql-action" => {
        "patterns" => ["github/codeql-action"],
      },
    },
  }] + [
    ["npm", "/flowersec-ts", {
      "ignore" => [{
        "dependency-name" => "tr46",
        "versions" => [">= 6.0.0"],
      }],
    }],
    ["gomod", "/flowersec-go", {
      "groups" => {
        "quic-stack" => {
          "patterns" => [
            "github.com/quic-go/quic-go",
            "github.com/quic-go/webtransport-go",
          ],
        },
      },
    }],
    ["gomod", "/tools/idlgen"],
    ["gomod", "/tools/releasenotes"],
    ["gomod", "/tools/stabilitycheck"],
    ["cargo", "/flowersec-rust", {
      "ignore" => [{
        "dependency-name" => "idna_mapping",
        "versions" => [">= 1.1.0"],
      }, {
        "dependency-name" => "idna_adapter",
        "versions" => [">= 1.2.0"],
      }],
    }],
    ["cargo", "/flowersec-native-transport"],
    ["cargo", "/flowersec-node-native"],
    ["cargo", "/flowersec-rust/fuzz"],
    ["cargo", "/examples/rust"],
    ["swift", "/"],
    ["swift", "/examples/swift"],
].map { |entry|
  ecosystem, directory, extra = entry
  {
    "package-ecosystem" => ecosystem,
    "directory" => directory,
    "schedule" => { "interval" => "weekly" },
  }.merge(extra || {})
},
}, "Dependabot configuration")

[release_workflow, rust_workflow, ci_workflow, codeql_workflow].each do |workflow|
  require_exact_keys(workflow, ["name", true, "env", "permissions", "jobs"], "workflow #{workflow["name"].inspect}")
  require_exact_value(workflow["env"], { "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24" => "true" }, "workflow #{workflow["name"].inspect} environment")
end
require_exact_value(ci_workflow[true], {
  "push" => { "branches" => ["main"] },
  "pull_request" => { "branches" => ["main"] },
}, "hosted CI triggers")
require_exact_value(codeql_workflow[true], {
  "workflow_dispatch" => {},
  "push" => { "branches" => ["main"] },
  "pull_request" => { "branches" => ["main"] },
  "schedule" => [{ "cron" => "17 3 * * *" }],
}, "CodeQL triggers")
require_exact_keys(scorecard_workflow, ["name", true, "permissions", "jobs"], "the Scorecard workflow")
require_exact_value(scorecard_workflow[true], {
  "push" => { "branches" => ["main"] },
  "schedule" => [{ "cron" => "30 1 * * 6" }],
}, "Scorecard triggers")
require_exact_value(scorecard_workflow["permissions"], "read-all", "Scorecard workflow permissions")
require_exact_value(ci_workflow["permissions"], { "contents" => "read" }, "hosted CI permissions")
require_exact_value(codeql_workflow["permissions"], { "contents" => "read" }, "CodeQL permissions")
require_exact_value(release_workflow[true], {
  "push" => { "tags" => ["flowersec-go/v*"] },
  "workflow_dispatch" => { "inputs" => { "version" => {
    "description" => "Existing coordinated release version to recover",
    "required" => true,
    "type" => "string",
  }, "mode" => {
    "description" => "Recovery scope",
    "required" => true,
    "default" => "full",
    "type" => "choice",
    "options" => ["full", "npm-only"],
  } } },
}, "unified release triggers")
require_exact_value(release_workflow["permissions"], { "contents" => "read" }, "unified release permissions")
require_exact_value(rust_workflow[true], {
  "workflow_call" => { "inputs" => { "version" => {
    "description" => "Rust crate version to publish",
    "required" => true,
    "type" => "string",
  } } },
  "workflow_dispatch" => { "inputs" => { "version" => {
    "description" => "Rust crate version to recover",
    "required" => true,
    "type" => "string",
  } } },
}, "Rust recovery triggers")
require_exact_value(rust_workflow["permissions"], { "contents" => "read" }, "Rust recovery permissions")

release_jobs = require_hash(release_workflow["jobs"], "the unified release workflow jobs")
rust_jobs = require_hash(rust_workflow["jobs"], "the Rust recovery workflow jobs")
ci_jobs = require_hash(ci_workflow["jobs"], "the hosted CI workflow jobs")
codeql_jobs = require_hash(codeql_workflow["jobs"], "the CodeQL workflow jobs")
scorecard_jobs = require_hash(scorecard_workflow["jobs"], "the Scorecard workflow jobs")
require_exact_keys(release_jobs, ["prepare", "rust-publish", "native-prebuilt", "release", "npm-recovery", "npm-consumer-smoke"], "the unified release workflow jobs")
require_exact_keys(rust_jobs, ["publish"], "the Rust recovery workflow jobs")
require_exact_keys(ci_jobs, ["repository", "precommit", "node-current", "dependency-review"], "the hosted CI workflow jobs")
require_exact_keys(codeql_jobs, ["plan", "analyze"], "the CodeQL workflow jobs")
require_exact_keys(scorecard_jobs, ["analysis"], "the Scorecard workflow jobs")

prepare_job = require_job(release_workflow, "prepare", "the unified release workflow")
release_job = require_job(release_workflow, "release", "the unified release workflow")
rust_reuse_job = require_job(release_workflow, "rust-publish", "the unified release workflow")
native_prebuilt_job = require_job(release_workflow, "native-prebuilt", "the unified release workflow")
npm_consumer_job = require_job(release_workflow, "npm-consumer-smoke", "the unified release workflow")
npm_recovery_job = require_job(release_workflow, "npm-recovery", "the unified release workflow")
rust_publish_job = require_job(rust_workflow, "publish", "the Rust recovery workflow")
repository_job = require_job(ci_workflow, "repository", "the hosted CI workflow")
precommit_job = require_job(ci_workflow, "precommit", "the hosted CI workflow")
node_current_job = require_job(ci_workflow, "node-current", "the hosted CI workflow")
dependency_review_job = require_job(ci_workflow, "dependency-review", "the hosted CI workflow")
codeql_job = require_job(codeql_workflow, "analyze", "the CodeQL workflow")
codeql_plan_job = require_job(codeql_workflow, "plan", "the CodeQL workflow")
scorecard_job = require_job(scorecard_workflow, "analysis", "the Scorecard workflow")

require_exact_keys(prepare_job, ["runs-on", "outputs", "steps"], "the unified release workflow prepare job")
require_exact_keys(release_job, ["needs", "if", "runs-on", "permissions", "steps"], "the unified release workflow release job")
require_exact_keys(rust_reuse_job, ["needs", "if", "permissions", "uses", "with"], "the unified release workflow rust-publish job")
require_exact_keys(native_prebuilt_job, ["needs", "if", "strategy", "runs-on", "permissions", "steps"], "the unified release workflow native-prebuilt job")
require_exact_keys(npm_recovery_job, ["needs", "if", "runs-on", "permissions", "steps"], "the unified release workflow npm recovery job")
require_exact_keys(npm_consumer_job, ["needs", "if", "strategy", "runs-on", "permissions", "steps"], "the unified release workflow npm consumer job")
require_exact_keys(rust_publish_job, ["runs-on", "permissions", "steps"], "the Rust recovery workflow publish job")
require_exact_keys(repository_job, ["runs-on", "steps"], "the hosted CI repository job")
require_exact_keys(precommit_job, ["name", "runs-on", "timeout-minutes", "env", "steps"], "the hosted CI precommit job")
require_exact_keys(node_current_job, ["name", "runs-on", "timeout-minutes", "steps"], "the hosted CI current Node job")
require_exact_keys(dependency_review_job, ["name", "if", "runs-on", "timeout-minutes", "steps"], "the hosted CI dependency review job")
require_exact_value(precommit_job["name"], "Precommit quality gate", "the hosted CI precommit job name")
require_exact_value(precommit_job["runs-on"], "macos-26", "the hosted CI precommit runner")
require_exact_value(precommit_job["timeout-minutes"], 60, "the hosted CI precommit timeout")
require_exact_value(precommit_job["env"], {
  "DEVELOPER_DIR" => "/Applications/Xcode_26.4.1.app/Contents/Developer",
}, "the hosted CI precommit Xcode selection")
require_exact_value(node_current_job["name"], "Current Node compatibility", "the hosted CI current Node job name")
require_exact_value(node_current_job["runs-on"], "ubuntu-latest", "the hosted CI current Node runner")
require_exact_value(node_current_job["timeout-minutes"], 10, "the hosted CI current Node timeout")
require_exact_value(dependency_review_job["name"], "Dependency review", "the hosted CI dependency review job name")
require_exact_value(dependency_review_job["runs-on"], "ubuntu-latest", "the hosted CI dependency review runner")
require_exact_value(dependency_review_job["timeout-minutes"], 5, "the hosted CI dependency review timeout")
require_exact_keys(codeql_plan_job, ["name", "runs-on", "timeout-minutes", "permissions", "outputs", "steps"], "the CodeQL plan job")
require_exact_value(codeql_plan_job["name"], "Plan scheduled analysis", "the CodeQL plan job name")
require_exact_value(codeql_plan_job["runs-on"], "ubuntu-latest", "the CodeQL plan runner")
require_exact_value(codeql_plan_job["timeout-minutes"], 1, "the CodeQL plan timeout")
require_exact_value(codeql_plan_job["permissions"], {
  "actions" => "read",
  "contents" => "read",
}, "the CodeQL plan permissions")
require_exact_value(codeql_plan_job["outputs"], {
  "should_scan" => "${{ steps.changes.outputs.should_scan }}",
}, "the CodeQL plan outputs")
require_exact_keys(codeql_job, ["name", "needs", "if", "runs-on", "timeout-minutes", "permissions", "strategy", "steps"], "the CodeQL analyze job")
require_exact_value(codeql_job["name"], "Analyze (${{ matrix.language }})", "the CodeQL job name")
require_exact_value(codeql_job["needs"], "plan", "the CodeQL analyze dependency")
require_exact_value(codeql_job["runs-on"], "${{ matrix.runner }}", "the CodeQL runner selector")
require_exact_value(codeql_job["timeout-minutes"], 45, "the CodeQL timeout")
require_exact_value(codeql_job["permissions"], {
  "actions" => "read",
  "contents" => "read",
  "security-events" => "write",
}, "the CodeQL analyze permissions")
require_exact_value(codeql_job["strategy"], {
  "fail-fast" => false,
  "matrix" => { "include" => [
    { "language" => "actions", "build-mode" => "none", "runner" => "ubuntu-latest" },
    { "language" => "c-cpp", "build-mode" => "none", "runner" => "ubuntu-latest" },
    { "language" => "go", "build-mode" => "autobuild", "runner" => "ubuntu-latest" },
    { "language" => "javascript-typescript", "build-mode" => "none", "runner" => "ubuntu-latest" },
    { "language" => "ruby", "build-mode" => "none", "runner" => "ubuntu-latest" },
    { "language" => "rust", "build-mode" => "none", "runner" => "ubuntu-latest" },
    { "language" => "swift", "build-mode" => "manual", "runner" => "macos-26" },
  ] },
}, "the CodeQL matrix")
require_exact_keys(scorecard_job, ["name", "runs-on", "timeout-minutes", "permissions", "steps"], "the Scorecard analysis job")
require_exact_value(scorecard_job["name"], "OpenSSF Scorecard", "the Scorecard job name")
require_exact_value(scorecard_job["runs-on"], "ubuntu-latest", "the Scorecard runner")
require_exact_value(scorecard_job["timeout-minutes"], 10, "the Scorecard timeout")
require_exact_value(scorecard_job["permissions"], {
  "security-events" => "write",
  "id-token" => "write",
}, "the Scorecard job permissions")
require_exact_value(prepare_job["outputs"], {
  "version" => "${{ steps.version.outputs.version }}",
  "mode" => "${{ steps.version.outputs.mode }}",
}, "the prepare job outputs")
require_exact_value(rust_reuse_job["needs"], "prepare", "the rust-publish job dependency")
require_exact_value(rust_reuse_job["permissions"], {
  "contents" => "read",
  "id-token" => "write",
}, "the rust-publish job permissions")
require_exact_value(rust_reuse_job["with"], { "version" => "${{ needs.prepare.outputs.version }}" }, "the rust-publish job inputs")
require_exact_value(release_job["needs"], ["prepare", "rust-publish", "native-prebuilt"], "the release job dependency")
require_exact_value(release_job["permissions"], {
  "contents" => "write",
  "packages" => "write",
  "id-token" => "write",
}, "the release job permissions")
require_exact_value(rust_publish_job["permissions"], {
  "contents" => "read",
  "id-token" => "write",
}, "the Rust recovery publish permissions")
require_exact_value(native_prebuilt_job["needs"], "prepare", "the native-prebuilt job dependency")
require_exact_value(native_prebuilt_job["runs-on"], "${{ matrix.runner }}", "the native-prebuilt runner selector")
require_exact_value(native_prebuilt_job["permissions"], { "contents" => "read" }, "the native-prebuilt permissions")
require_exact_value(native_prebuilt_job["strategy"], {
  "fail-fast" => false,
  "matrix" => { "include" => [
    { "platform" => "darwin-arm64", "runner" => "macos-15", "target" => "aarch64-apple-darwin" },
    { "platform" => "darwin-x64", "runner" => "macos-15-intel", "target" => "x86_64-apple-darwin" },
    { "platform" => "linux-arm64-gnu", "runner" => "ubuntu-24.04-arm", "target" => "aarch64-unknown-linux-gnu" },
    { "platform" => "linux-x64-gnu", "runner" => "ubuntu-latest", "target" => "x86_64-unknown-linux-gnu" },
  ] },
}, "the native-prebuilt matrix")
require_exact_value(npm_recovery_job["needs"], "prepare", "the npm recovery job dependency")
require_exact_value(npm_recovery_job["runs-on"], "ubuntu-latest", "the npm recovery runner")
require_exact_value(npm_recovery_job["permissions"], {
  "contents" => "read",
  "id-token" => "write",
}, "the npm recovery permissions")
require_exact_value(npm_consumer_job["needs"], ["prepare", "release", "npm-recovery"], "the npm consumer job dependency")
require_exact_value(npm_consumer_job["runs-on"], "${{ matrix.runner }}", "the npm consumer runner selector")
require_exact_value(npm_consumer_job["permissions"], { "contents" => "read" }, "the npm consumer permissions")
require_exact_value(npm_consumer_job["strategy"], {
  "fail-fast" => false,
  "matrix" => { "include" => [
    { "runner" => "macos-15" },
    { "runner" => "macos-15-intel" },
    { "runner" => "ubuntu-24.04-arm" },
    { "runner" => "ubuntu-latest" },
  ] },
}, "the npm consumer matrix")

[
  [prepare_job, "the unified release workflow prepare job"],
  [rust_publish_job, "the Rust recovery workflow publish job"],
  [repository_job, "the hosted CI repository job"],
  [precommit_job, "the hosted CI precommit job"],
  [node_current_job, "the hosted CI current Node job"],
  [codeql_plan_job, "the CodeQL plan job"],
  [scorecard_job, "the Scorecard analysis job"],
].each { |job, context| require_unconditional(job, context) }
require_condition_value(release_job, "needs.prepare.outputs.mode == 'full'", "the unified release workflow release job")
require_condition_value(rust_reuse_job, "needs.prepare.outputs.mode == 'full'", "the unified release workflow rust-publish job")
require_condition_value(native_prebuilt_job, "needs.prepare.outputs.mode == 'full'", "the unified release workflow native-prebuilt job")
require_condition_value(npm_recovery_job, "needs.prepare.outputs.mode == 'npm-only'", "the unified release workflow npm recovery job")
require_condition_value(npm_consumer_job, "always() && needs.prepare.result == 'success' && ((needs.prepare.outputs.mode == 'full' && needs.release.result == 'success') || (needs.prepare.outputs.mode == 'npm-only' && needs.npm-recovery.result == 'success'))", "the unified release workflow npm consumer job")
require_condition_value(dependency_review_job, "github.event_name == 'pull_request'", "the hosted CI dependency review job")
require_condition(codeql_job["if"] == "needs.plan.outputs.should_scan == 'true'", "the CodeQL analyze job must use only the approved condition")

require_condition(prepare_job["runs-on"] == "ubuntu-latest", "the unified release workflow prepare job must run on ubuntu-latest")
require_condition(release_job["runs-on"] == "ubuntu-latest", "the unified release workflow release job must run on ubuntu-latest")
require_condition(rust_reuse_job["uses"] == "./.github/workflows/rust-release.yml", "the unified release workflow rust-publish job must call the reviewed workflow")
require_condition(native_prebuilt_job["runs-on"] == "${{ matrix.runner }}", "the native-prebuilt job must select its reviewed platform runner")
require_condition(rust_publish_job["runs-on"] == "ubuntu-latest", "the Rust recovery workflow publish job must run on ubuntu-latest")

release_steps = require_steps(release_job, "the unified release workflow release job")
rust_steps = require_steps(rust_publish_job, "the Rust recovery workflow publish job")
native_prebuilt_steps = require_steps(native_prebuilt_job, "the unified release workflow native-prebuilt job")
npm_consumer_steps = require_steps(npm_consumer_job, "the unified release workflow npm consumer job")
npm_recovery_steps = require_steps(npm_recovery_job, "the unified release workflow npm recovery job")
ci_steps = require_steps(repository_job, "the hosted CI repository job")
precommit_steps = require_steps(precommit_job, "the hosted CI precommit job")
node_current_steps = require_steps(node_current_job, "the hosted CI current Node job")
dependency_review_steps = require_steps(dependency_review_job, "the hosted CI dependency review job")
codeql_steps = require_steps(codeql_job, "the CodeQL analyze job")
codeql_plan_steps = require_steps(codeql_plan_job, "the CodeQL plan job")
scorecard_steps = require_steps(scorecard_job, "the Scorecard analysis job")
prepare_steps = require_steps(prepare_job, "the unified release workflow prepare job")

checkout = { "uses" => "actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "with" => { "fetch-depth" => 0 } }
release_checkout = {
  "uses" => "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
  "with" => {
    "fetch-depth" => 0,
    "ref" => "refs/tags/flowersec-go/v${{ needs.prepare.outputs.version }}",
  },
}
validate_step_contracts(prepare_steps, [
  { name: "Resolve release version", keys: ["name", "id", "env", "run"], values: {
    "id" => "version",
    "env" => {
      "RELEASE_VERSION_INPUT" => "${{ inputs.version }}",
      "RELEASE_MODE_INPUT" => "${{ inputs.mode }}",
    },
  }, run_sha256: "a6ae5453b78e4d35fcfd50e172b465130f1e159898b009cb9a7154503f7ab7c7" },
], "the unified release workflow prepare job")
validate_step_contracts(ci_steps, [
  { name: nil, keys: ["uses", "with"], values: checkout },
  { name: "Check changed lines", keys: ["name", "env", "run"], values: { "env" => { "BEFORE_SHA" => "${{ github.event.before }}", "BASE_SHA" => "${{ github.event.pull_request.base.sha }}" } }, run_sha256: "a2ec5f19c1131255e166da2837951a99a958bb074bbdcaf48bd06b11710159a7" },
  { name: "Check shell syntax", keys: ["name", "run"], run_sha256: "37f031d1ced8b2c2554b688709bc5a7faecfee38d494f87d9f4da00284209b0a" },
  { name: "Check release workflow policy", keys: ["name", "run"], run_sha256: "ca5a81f1c6229ace59783918c84158923cedda3a99d4135a5e95fd812242a47d" },
], "the hosted CI repository job")
validate_step_contracts(precommit_steps, [
  { name: nil, keys: ["uses", "with"], values: checkout },
  { name: "Setup Go", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff",
    "with" => {
      "go-version-file" => "flowersec-go/go.mod",
      "cache" => true,
      "cache-dependency-path" => "flowersec-go/go.sum\ntools/idlgen/go.sum\ntools/releasenotes/go.sum\ntools/stabilitycheck/go.sum\n",
    },
  } },
  { name: "Setup Node", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
    "with" => { "node-version" => "20.19.0", "cache" => "npm", "cache-dependency-path" => "flowersec-ts/package-lock.json" },
  } },
  { name: "Setup Rust", keys: ["name", "uses", "with"], values: {
    "uses" => "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4",
    "with" => { "toolchain" => "1.88.0", "components" => "rustfmt,clippy" },
  } },
  { name: "Run precommit quality gate", keys: ["name", "run"], values: { "run" => "make precommit" } },
], "the hosted CI precommit job")
validate_step_contracts(node_current_steps, [
  { name: nil, keys: ["uses", "with"], values: checkout },
  { name: "Setup current Node", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
    "with" => { "node-version" => "24", "cache" => "npm", "cache-dependency-path" => "flowersec-ts/package-lock.json" },
  } },
  { name: "Run TypeScript language lane", keys: ["name", "run"], values: { "run" => "make ts-ci ts-build ts-test-short" } },
], "the hosted CI current Node job")
validate_step_contracts(dependency_review_steps, [
  { name: nil, keys: ["uses", "with"], values: {
    "uses" => "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
    "with" => { "persist-credentials" => false },
  } },
  { name: "Review dependency changes", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294",
    "with" => { "fail-on-severity" => "high", "retry-on-snapshot-warnings" => true },
  } },
], "the hosted CI dependency review job")
validate_step_contracts(codeql_steps, [
  { name: nil, keys: ["uses"], values: { "uses" => "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" } },
  { name: "Resolve Swift cache key", keys: ["name", "if", "id", "run"], values: { "if" => "matrix.language == 'swift'", "id" => "swift-cache-key", "run" => "swift --version | shasum -a 256 | awk '{ print \"toolchain=\" $1 }' >> \"$GITHUB_OUTPUT\"\n" } },
  { name: "Restore Swift build cache", keys: ["name", "if", "uses", "with"], values: { "if" => "matrix.language == 'swift'", "uses" => "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9", "with" => { "path" => ".build", "key" => "swift-codeql-${{ runner.os }}-${{ steps.swift-cache-key.outputs.toolchain }}-${{ hashFiles('Package.swift', 'Package.resolved') }}" } } },
  { name: "Prepare Swift build cache", keys: ["name", "if", "run"], values: { "if" => "matrix.language == 'swift'", "run" => "swift package --skip-update --only-use-versions-from-resolved-file resolve\nswift build --skip-update --only-use-versions-from-resolved-file --target Flowersec -j 8\n" } },
  { name: "Initialize CodeQL", keys: ["name", "uses", "with"], values: { "uses" => "github/codeql-action/init@5595ccaf912efad79be6eef63a5619ff05969be3", "with" => { "languages" => "${{ matrix.language }}", "build-mode" => "${{ matrix.build-mode }}", "queries" => "security-extended" } } },
  { name: "Build Swift library", keys: ["name", "if", "run"], values: { "if" => "matrix.language == 'swift'", "run" => "find flowersec-swift/Sources/Flowersec -type f -name '*.swift' -exec touch {} +\nswift build --skip-update --only-use-versions-from-resolved-file --target Flowersec -j 8\n" } },
  { name: "Autobuild Go", keys: ["name", "if", "uses"], values: { "if" => "matrix.language == 'go'", "uses" => "github/codeql-action/autobuild@5595ccaf912efad79be6eef63a5619ff05969be3" } },
  { name: "Analyze", keys: ["name", "uses"], values: { "uses" => "github/codeql-action/analyze@5595ccaf912efad79be6eef63a5619ff05969be3" } },
], "the CodeQL analyze job")
validate_step_contracts(codeql_plan_steps, [
  { name: "Check for new main commits", keys: ["name", "id", "env", "run"], values: {
    "id" => "changes",
    "env" => {
      "API_URL" => "${{ github.api_url }}",
      "EVENT_NAME" => "${{ github.event_name }}",
      "GH_TOKEN" => "${{ github.token }}",
      "HEAD_SHA" => "${{ github.sha }}",
      "REPOSITORY" => "${{ github.repository }}",
    },
  }, run_sha256: "6a94dacb488f0128af696fe2a8ae43f23b78c31b4132f409ea72cfbc20297ce6" },
], "the CodeQL plan job")
validate_step_contracts(scorecard_steps, [
  { name: "Checkout repository", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "with" => { "persist-credentials" => false },
  } },
  { name: "Run Scorecard analysis", keys: ["name", "uses", "with"], values: {
    "uses" => "ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc",
    "with" => { "results_file" => "results.sarif", "results_format" => "sarif", "publish_results" => true },
  } },
  { name: "Upload Scorecard artifact", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "with" => { "name" => "scorecard-results", "path" => "results.sarif", "retention-days" => 5 },
  } },
  { name: "Upload Scorecard results", keys: ["name", "uses", "with"], values: {
    "uses" => "github/codeql-action/upload-sarif@5595ccaf912efad79be6eef63a5619ff05969be3",
    "with" => { "sarif_file" => "results.sarif" },
  } },
], "the Scorecard analysis job")
validate_step_contracts(release_steps, [
  { name: nil, keys: ["uses", "with"], values: release_checkout },
  { name: "Compute version vars", keys: ["name", "id", "env", "run"], values: {
    "id" => "vars",
    "env" => { "RELEASE_VERSION_INPUT" => "${{ needs.prepare.outputs.version }}" },
  }, run_sha256: "1e2b49d667841468c895f18da4398191530b1ae1796ea1108ffdc3e4b4deadec" },
  { name: "Setup Go", keys: ["name", "uses", "with"], values: { "uses" => "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff", "with" => { "go-version-file" => "flowersec-go/go.mod", "cache" => true, "cache-dependency-path" => "flowersec-go/go.sum" } } },
  { name: "Setup Node", keys: ["name", "uses", "with"], values: { "uses" => "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", "with" => { "node-version" => "24", "registry-url" => "https://registry.npmjs.org", "cache" => "npm", "cache-dependency-path" => "flowersec-ts/package-lock.json" } } },
  { name: "Ensure npm supports trusted publishing (OIDC)", keys: ["name", "run"], run_sha256: "fb7f479c6c90ad6363c5368e126e136be6cb4808b20328f2476fea0230aeea0e" },
  { name: "Setup Rust", keys: ["name", "uses"], values: { "uses" => "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4" } },
  { name: "Validate release version facts", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_VERSION" => "${{ steps.vars.outputs.version }}" } }, run_sha256: "9431ce4342dcd8f8af90607321f1ceb9e6e61c13f455b06acd242d96f53e0087" },
  { name: "Verify all language tags point to this commit", keys: ["name", "env", "run"], values: { "env" => {
    "RELEASE_VERSION" => "${{ steps.vars.outputs.version }}",
    "RELEASE_SHA" => "${{ steps.vars.outputs.sha }}",
  } }, run_sha256: "2dc2aa66b184f05c334e60ef6d1ca9421fc40c42ace1a5e74f6236355f3b8613" },
  { name: "Download native prebuilt packages", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "with" => { "pattern" => "flowersec-node-native-*", "path" => "native-prebuilt", "merge-multiple" => false },
  } },
  { name: "Build release artifacts", keys: ["name", "env", "run"], values: { "env" => {
    "RELEASE_DATE" => "${{ steps.vars.outputs.date }}",
    "RELEASE_SHA" => "${{ steps.vars.outputs.sha }}",
    "RELEASE_VERSION" => "${{ steps.vars.outputs.version }}",
  } }, run_sha256: "cb8966cd3310f94f7dbef013761d81bd3d5e91b62fdbc175975212374ffe8c56" },
  { name: "Generate release notes", keys: ["name", "env", "run"], values: { "env" => {
    "RELEASE_SHA" => "${{ steps.vars.outputs.sha }}",
    "RELEASE_TAG" => "${{ steps.vars.outputs.tag }}",
  } }, run_sha256: "1bd88ea62d5cfa76a864986943ea296ec1def96e507dcdb60077ac446e1f2658" },
  { name: "Publish GitHub Release", keys: ["name", "uses", "with"], values: { "uses" => "softprops/action-gh-release@3d0d9888cb7fd7b750713d6e236d1fcb99157228", "with" => {
    "files" => "dist/*\n",
    "body_path" => "release-notes.md",
    "tag_name" => "${{ steps.vars.outputs.tag }}",
  } } },
  { name: "Setup Docker Buildx", keys: ["name", "uses", "with"], values: { "uses" => "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c", "with" => { "driver-opts" => "image=moby/buildkit:buildx-stable-1@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec" } } },
  { name: "Login to GHCR", keys: ["name", "uses", "with"], values: { "uses" => "docker/login-action@dbcb813823bdd20940b903addbd779551569679f", "with" => { "registry" => "ghcr.io", "username" => "${{ github.actor }}", "password" => "${{ secrets.GITHUB_TOKEN }}" } } },
  { name: "Build and push runtime image", keys: ["name", "uses", "with"], values: { "uses" => "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8", "with" => {
    "context" => ".",
    "file" => "docker/flowersec-runtime/Dockerfile",
    "platforms" => "linux/amd64,linux/arm64",
    "push" => true,
    "sbom" => true,
    "tags" => "ghcr.io/${{ github.repository_owner }}/flowersec-runtime:${{ steps.vars.outputs.version }}\nghcr.io/${{ github.repository_owner }}/flowersec-runtime:latest\n",
    "build-args" => "VERSION=v${{ steps.vars.outputs.version }}\nCOMMIT=${{ steps.vars.outputs.sha }}\nDATE=${{ steps.vars.outputs.date }}\n",
  } } },
  { name: "Publish npm packages with dependency barriers", keys: ["name", "env", "run"], values: { "env" => {
    "RELEASE_VERSION" => "${{ steps.vars.outputs.version }}",
    "RELEASE_SHA" => "${{ steps.vars.outputs.sha }}",
  } }, run_sha256: "8972e0612f98fd0de5a8b06f0945e153d3b50bd71086baf3295cb3441a9153cc" },
], "the unified release workflow release job")
validate_step_contracts(native_prebuilt_steps, [
  { name: nil, keys: ["uses", "with"], values: {
    "uses" => "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
    "with" => { "ref" => "refs/tags/flowersec-go/v${{ needs.prepare.outputs.version }}" },
  } },
  { name: "Setup Rust", keys: ["name", "uses", "with"], values: {
    "uses" => "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4",
    "with" => { "targets" => "${{ matrix.target }}" },
  } },
  { name: "Setup Node", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
    "with" => { "node-version" => "20.19.0" },
  } },
  { name: "Build native addon", keys: ["name", "env", "run"], values: { "env" => {
    "NATIVE_TARGET" => "${{ matrix.target }}",
    "NATIVE_PLATFORM" => "${{ matrix.platform }}",
  } }, run_sha256: "690e76440261910d312f4d3078fa5dff71b134ecbc6229c81d14b72d29a26685" },
  { name: "Smoke test native addon", keys: ["name", "env", "run"], values: { "env" => {
    "FLOWERSEC_NATIVE_ADDON_PATH" => "${{ github.workspace }}/native-package/${{ matrix.platform }}/flowersec-node-native.${{ matrix.platform }}.node",
  } }, run_sha256: "d904f71a6438c51ed1aacc963893a8004a70f9168f16b4c603c6702e3d42bb63" },
  { name: "Upload native prebuilt", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "with" => {
      "name" => "flowersec-node-native-${{ matrix.platform }}",
      "path" => "native-package/${{ matrix.platform }}",
      "if-no-files-found" => "error",
    },
  } },
], "the unified release workflow native-prebuilt job")
validate_step_contracts(npm_recovery_steps, [
  { name: nil, keys: ["uses", "with"], values: release_checkout },
  { name: "Setup Node", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
    "with" => { "node-version" => "24", "registry-url" => "https://registry.npmjs.org" },
  } },
  { name: "Recover npm registry packages from immutable release assets", keys: ["name", "env", "run"], values: { "env" => {
    "GH_TOKEN" => "${{ github.token }}",
    "RELEASE_VERSION" => "${{ needs.prepare.outputs.version }}",
  } }, run_sha256: "28f3012d07ab19889e7cbba9b6466aadfbc5a060dc880e6174b526c1b8f96972" },
], "the unified release workflow npm recovery job")
validate_step_contracts(npm_consumer_steps, [
  { name: nil, keys: ["uses", "with"], values: {
    "uses" => "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
    "with" => { "ref" => "refs/tags/flowersec-go/v${{ needs.prepare.outputs.version }}" },
  } },
  { name: "Setup Node", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
    "with" => { "node-version" => "20.19.0", "registry-url" => "https://registry.npmjs.org" },
  } },
  { name: "Setup Go", keys: ["name", "uses", "with"], values: {
    "uses" => "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff",
    "with" => { "go-version-file" => "flowersec-go/go.mod", "cache" => false },
  } },
  { name: "Verify registry consumer install and load", keys: ["name", "env", "run"], values: { "env" => {
    "RELEASE_VERSION" => "${{ needs.prepare.outputs.version }}",
  } }, run_sha256: "60dfc6c71b5fcb8dec7d17777678d62aa94c0aba810e1e168861c176a9dfeb65" },
], "the unified release workflow npm consumer job")

validate_step_contracts(rust_steps, [
  { name: nil, keys: ["uses", "with"], values: checkout },
  { name: "Checkout release commit", keys: ["name", "id", "env", "run"], values: { "id" => "version", "env" => { "RELEASE_VERSION_INPUT" => "${{ inputs.version }}" } }, run_sha256: "ac06a1217c1f7df7c9e899d1fd91e3eb5a9c16f30aba50503028c62b391ac398" },
  { name: "Setup Rust", keys: ["name", "uses"], values: { "uses" => "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4" } },
  { name: "Validate release version facts", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_VERSION" => "${{ steps.version.outputs.version }}" } }, run_sha256: "9431ce4342dcd8f8af90607321f1ceb9e6e61c13f455b06acd242d96f53e0087" },
  { name: "Verify release tags", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_VERSION" => "${{ steps.version.outputs.version }}" } }, run_sha256: "3e5e103b4b32e468d370d25613885b564a2f9f0dfebe2ced9b182a1691038830" },
  { name: "Check whether native transport version is already published", keys: ["name", "id", "env", "run"], values: { "id" => "native-published", "env" => { "RELEASE_VERSION" => "${{ steps.version.outputs.version }}" } }, run_sha256: "35043da6ab7f3b9809adc65264a983823eb3020507fb191256aeacf903bc29ba" },
  { name: "Authenticate native transport publication", keys: ["name", "if", "id", "uses"], values: { "if" => "steps.native-published.outputs.exists != 'true'", "id" => "native-auth", "uses" => "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18" } },
  { name: "Publish native transport crate", keys: ["name", "if", "working-directory", "env", "run"], values: { "if" => "steps.native-published.outputs.exists != 'true'", "working-directory" => "flowersec-native-transport", "env" => { "CARGO_REGISTRY_TOKEN" => "${{ steps.native-auth.outputs.token }}" } }, run_sha256: "0990bd3b2f0dd14204dc600e8a8bce3fd1e41ab5a6404e75e59f7c41b49ea0d5" },
  { name: "Wait for native transport registry readback", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_VERSION" => "${{ steps.version.outputs.version }}" } }, run_sha256: "55c8d909b7748b4ed9596feb4556a426d474b5355c9321075b74b456554bb93d" },
  { name: "Check whether Flowersec Rust SDK version is already published", keys: ["name", "id", "env", "run"], values: { "id" => "sdk-published", "env" => { "RELEASE_VERSION" => "${{ steps.version.outputs.version }}" } }, run_sha256: "712e2393343ff375abca1a8046cc8aa0b85be961fda34cc5125f7397248d5de0" },
  { name: "Authenticate Flowersec Rust SDK publication", keys: ["name", "if", "id", "uses"], values: { "if" => "steps.sdk-published.outputs.exists != 'true'", "id" => "sdk-auth", "uses" => "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18" } },
  { name: "Publish Flowersec Rust SDK", keys: ["name", "if", "working-directory", "env", "run"], values: { "if" => "steps.sdk-published.outputs.exists != 'true'", "working-directory" => "flowersec-rust", "env" => { "CARGO_REGISTRY_TOKEN" => "${{ steps.sdk-auth.outputs.token }}" } }, run_sha256: "0990bd3b2f0dd14204dc600e8a8bce3fd1e41ab5a6404e75e59f7c41b49ea0d5" },
  { name: "Verify Flowersec Rust SDK registry readback", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_VERSION" => "${{ steps.version.outputs.version }}" } }, run_sha256: "5d0dee062187ebcd7c435a23d84b5e8c4992ebd9a70f6b6b2b50f2cff26f140b" },
], "the Rust recovery workflow publish job")

reject_publication_before(release_steps, 8, "the unified release workflow")
reject_publication_before(rust_steps, 5, "the Rust recovery workflow")

release_setup, release_setup_index = require_named_step(release_steps, "Setup Rust", "the unified release workflow")
release_version, release_version_index = require_named_step(release_steps, "Validate release version facts", "the unified release workflow")
release_tags, release_tags_index = require_named_step(release_steps, "Verify all language tags point to this commit", "the unified release workflow")
require_step_field(release_setup, "uses", "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4", "the unified release workflow Setup Rust step")
require_step_field(release_version, "run", 'node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"', "the unified release workflow version facts step")
require_step_field(release_tags, "run", 'scripts/verify-release-tags.sh "$RELEASE_VERSION" "$RELEASE_SHA"', "the unified release workflow tag verification step")
[release_setup, release_version, release_tags].each_with_index do |step, index|
  require_unconditional(step, "the unified release workflow validation step #{index + 1}")
end
require_condition(release_setup_index < release_version_index && release_version_index < release_tags_index, "the unified release workflow must run Rust setup, version validation, and tag verification in order")

release_publication_steps = [
  "Build release artifacts",
  "Generate release notes",
  "Publish GitHub Release",
  "Build and push runtime image",
  "Publish npm packages with dependency barriers",
]
release_publication_steps.each do |name|
  step, index = require_named_step(release_steps, name, "the unified release workflow")
  require_unconditional(step, "the unified release workflow publication step #{name}")
  require_condition(release_version_index < index && release_tags_index < index, "the unified release workflow must validate versions and tags before every publication step, including #{name}")
end

rust_setup, rust_setup_index = require_named_step(rust_steps, "Setup Rust", "the Rust recovery workflow")
rust_version, rust_version_index = require_named_step(rust_steps, "Validate release version facts", "the Rust recovery workflow")
rust_tags, rust_tags_index = require_named_step(rust_steps, "Verify release tags", "the Rust recovery workflow")
native_check, native_check_index = require_named_step(rust_steps, "Check whether native transport version is already published", "the Rust recovery workflow")
native_auth, native_auth_index = require_named_step(rust_steps, "Authenticate native transport publication", "the Rust recovery workflow")
native_publish, native_publish_index = require_named_step(rust_steps, "Publish native transport crate", "the Rust recovery workflow")
native_readback, native_readback_index = require_named_step(rust_steps, "Wait for native transport registry readback", "the Rust recovery workflow")
sdk_check, sdk_check_index = require_named_step(rust_steps, "Check whether Flowersec Rust SDK version is already published", "the Rust recovery workflow")
sdk_auth, sdk_auth_index = require_named_step(rust_steps, "Authenticate Flowersec Rust SDK publication", "the Rust recovery workflow")
sdk_publish, sdk_publish_index = require_named_step(rust_steps, "Publish Flowersec Rust SDK", "the Rust recovery workflow")
sdk_readback, sdk_readback_index = require_named_step(rust_steps, "Verify Flowersec Rust SDK registry readback", "the Rust recovery workflow")
require_step_field(rust_setup, "uses", "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4", "the Rust recovery workflow Setup Rust step")
require_step_field(rust_version, "run", 'node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"', "the Rust recovery workflow version facts step")
require_step_field(rust_tags, "run", 'scripts/verify-release-tags.sh "$RELEASE_VERSION" "$(git rev-parse HEAD)"', "the Rust recovery workflow tag verification step")
[rust_setup, rust_version, rust_tags].each_with_index do |step, index|
  require_unconditional(step, "the Rust recovery workflow validation step #{index + 1}")
end
require_unconditional(native_check, "the native transport publication step that checks existing versions")
require_unconditional(native_readback, "the native transport registry readback")
require_unconditional(sdk_check, "the Flowersec Rust SDK publication step that checks existing versions")
require_unconditional(sdk_readback, "the Flowersec Rust SDK registry readback")
require_condition_value(native_auth, "steps.native-published.outputs.exists != 'true'", "the native transport publication step that authenticates")
require_condition_value(native_publish, "steps.native-published.outputs.exists != 'true'", "the native transport publication step")
require_condition_value(sdk_auth, "steps.sdk-published.outputs.exists != 'true'", "the Flowersec Rust SDK publication step that authenticates")
require_condition_value(sdk_publish, "steps.sdk-published.outputs.exists != 'true'", "the Flowersec Rust SDK publication step")
require_condition(
  rust_setup_index < rust_version_index && rust_version_index < rust_tags_index &&
    rust_tags_index < native_check_index && native_check_index < native_auth_index &&
    native_auth_index < native_publish_index && native_publish_index < native_readback_index &&
    native_readback_index < sdk_check_index && sdk_check_index < sdk_auth_index &&
    sdk_auth_index < sdk_publish_index && sdk_publish_index < sdk_readback_index,
  "the Rust recovery workflow must publish and read back the native driver before the SDK",
)

ci_policy_step, = require_named_step(ci_steps, "Check release workflow policy", "the hosted CI workflow")
require_step_field(ci_policy_step, "run", "scripts/check-release-workflow-policy.sh", "the hosted CI policy step")
require_unconditional(ci_policy_step, "the hosted CI policy step")

puts "verified structured release workflows"
rescue PolicyError => error
  $stderr.puts error.message
  exit 1
end
