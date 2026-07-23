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

require_exact_keys(dependabot, ["version", "updates"], "Dependabot configuration")
require_exact_value(dependabot, {
  "version" => 2,
  "updates" => [{
    "package-ecosystem" => "github-actions",
    "directory" => "/",
    "schedule" => { "interval" => "weekly" },
  }],
}, "Dependabot configuration")

[release_workflow, rust_workflow, ci_workflow].each do |workflow|
  require_exact_keys(workflow, ["name", true, "env", "permissions", "jobs"], "workflow #{workflow["name"].inspect}")
  require_exact_value(workflow["env"], { "FORCE_JAVASCRIPT_ACTIONS_TO_NODE24" => "true" }, "workflow #{workflow["name"].inspect} environment")
end
require_exact_value(ci_workflow[true], {
  "push" => { "branches" => ["main"] },
  "pull_request" => { "branches" => ["main"] },
}, "hosted CI triggers")
require_exact_value(ci_workflow["permissions"], { "contents" => "read" }, "hosted CI permissions")
require_exact_value(release_workflow[true], { "push" => { "tags" => ["flowersec-go/v*"] } }, "unified release triggers")
require_exact_value(release_workflow["permissions"], {
  "contents" => "write",
  "packages" => "write",
  "id-token" => "write",
}, "unified release permissions")
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
require_exact_value(rust_workflow["permissions"], { "contents" => "read", "id-token" => "write" }, "Rust recovery permissions")

release_jobs = require_hash(release_workflow["jobs"], "the unified release workflow jobs")
rust_jobs = require_hash(rust_workflow["jobs"], "the Rust recovery workflow jobs")
ci_jobs = require_hash(ci_workflow["jobs"], "the hosted CI workflow jobs")
require_exact_keys(release_jobs, ["prepare", "rust-publish", "release"], "the unified release workflow jobs")
require_exact_keys(rust_jobs, ["publish"], "the Rust recovery workflow jobs")
require_exact_keys(ci_jobs, ["repository"], "the hosted CI workflow jobs")

prepare_job = require_job(release_workflow, "prepare", "the unified release workflow")
release_job = require_job(release_workflow, "release", "the unified release workflow")
rust_reuse_job = require_job(release_workflow, "rust-publish", "the unified release workflow")
rust_publish_job = require_job(rust_workflow, "publish", "the Rust recovery workflow")
repository_job = require_job(ci_workflow, "repository", "the hosted CI workflow")

require_exact_keys(prepare_job, ["runs-on", "outputs", "steps"], "the unified release workflow prepare job")
require_exact_keys(release_job, ["needs", "runs-on", "steps"], "the unified release workflow release job")
require_exact_keys(rust_reuse_job, ["needs", "uses", "with"], "the unified release workflow rust-publish job")
require_exact_keys(rust_publish_job, ["runs-on", "steps"], "the Rust recovery workflow publish job")
require_exact_keys(repository_job, ["runs-on", "steps"], "the hosted CI repository job")
require_exact_value(prepare_job["outputs"], { "version" => "${{ steps.version.outputs.version }}" }, "the prepare job outputs")
require_exact_value(rust_reuse_job["needs"], "prepare", "the rust-publish job dependency")
require_exact_value(rust_reuse_job["with"], { "version" => "${{ needs.prepare.outputs.version }}" }, "the rust-publish job inputs")
require_exact_value(release_job["needs"], "prepare", "the release job dependency")

[
  [prepare_job, "the unified release workflow prepare job"],
  [release_job, "the unified release workflow release job"],
  [rust_reuse_job, "the unified release workflow rust-publish job"],
  [rust_publish_job, "the Rust recovery workflow publish job"],
  [repository_job, "the hosted CI repository job"],
].each { |job, context| require_unconditional(job, context) }

require_condition(prepare_job["runs-on"] == "ubuntu-latest", "the unified release workflow prepare job must run on ubuntu-latest")
require_condition(release_job["runs-on"] == "ubuntu-latest", "the unified release workflow release job must run on ubuntu-latest")
require_condition(rust_reuse_job["uses"] == "./.github/workflows/rust-release.yml", "the unified release workflow rust-publish job must call the reviewed workflow")
require_condition(rust_publish_job["runs-on"] == "ubuntu-latest", "the Rust recovery workflow publish job must run on ubuntu-latest")

release_steps = require_steps(release_job, "the unified release workflow release job")
rust_steps = require_steps(rust_publish_job, "the Rust recovery workflow publish job")
ci_steps = require_steps(repository_job, "the hosted CI repository job")
prepare_steps = require_steps(prepare_job, "the unified release workflow prepare job")

checkout = { "uses" => "actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "with" => { "fetch-depth" => 0 } }
validate_step_contracts(prepare_steps, [
  { name: "Resolve release version", keys: ["name", "id", "run"], values: { "id" => "version" }, run_sha256: "adc448b028b8291fd461c54609cf5419d805b8fccae767e0ad031d9103663b36" },
], "the unified release workflow prepare job")
validate_step_contracts(ci_steps, [
  { name: nil, keys: ["uses", "with"], values: checkout },
  { name: "Check changed lines", keys: ["name", "env", "run"], values: { "env" => { "BEFORE_SHA" => "${{ github.event.before }}", "BASE_SHA" => "${{ github.event.pull_request.base.sha }}" } }, run_sha256: "a2ec5f19c1131255e166da2837951a99a958bb074bbdcaf48bd06b11710159a7" },
  { name: "Check shell syntax", keys: ["name", "run"], run_sha256: "37f031d1ced8b2c2554b688709bc5a7faecfee38d494f87d9f4da00284209b0a" },
  { name: "Check release workflow policy", keys: ["name", "run"], run_sha256: "ca5a81f1c6229ace59783918c84158923cedda3a99d4135a5e95fd812242a47d" },
], "the hosted CI repository job")
validate_step_contracts(release_steps, [
  { name: nil, keys: ["uses", "with"], values: checkout },
  { name: "Compute version vars", keys: ["name", "id", "run"], values: { "id" => "vars" }, run_sha256: "308142f97577687f8076c19a3f65c4de19c48196c1d9ab76349c9a2d7f3a08bd" },
  { name: "Setup Go", keys: ["name", "uses", "with"], values: { "uses" => "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff", "with" => { "go-version-file" => "flowersec-go/go.mod", "cache" => true, "cache-dependency-path" => "flowersec-go/go.sum" } } },
  { name: "Setup Node", keys: ["name", "uses", "with"], values: { "uses" => "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", "with" => { "node-version" => "24", "registry-url" => "https://registry.npmjs.org", "cache" => "npm", "cache-dependency-path" => "flowersec-ts/package-lock.json" } } },
  { name: "Ensure npm supports trusted publishing (OIDC)", keys: ["name", "run"], run_sha256: "fb7f479c6c90ad6363c5368e126e136be6cb4808b20328f2476fea0230aeea0e" },
  { name: "Setup Rust", keys: ["name", "uses"], values: { "uses" => "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4" } },
  { name: "Validate release version facts", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_VERSION" => "${{ steps.vars.outputs.version }}" } }, run_sha256: "9431ce4342dcd8f8af90607321f1ceb9e6e61c13f455b06acd242d96f53e0087" },
  { name: "Verify all language tags point to this commit", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_VERSION" => "${{ steps.vars.outputs.version }}" } }, run_sha256: "2e0b0a8195cac9968212ce6f5ad6aca14b46ecfb40ac4b6fad1e09cba78b4e60" },
  { name: "Build release artifacts", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_DATE" => "${{ steps.vars.outputs.date }}", "RELEASE_VERSION" => "${{ steps.vars.outputs.version }}" } }, run_sha256: "6cc25228e0df686a9aca9d2cc231a4a41d08b96be6d4c3f7e27d60a1c86dd15e" },
  { name: "Generate release notes", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_TAG" => "${{ steps.vars.outputs.tag }}" } }, run_sha256: "4def773734f95ee6a5f05876f4355923b9a3604bee521b26ce04ac77108086ad" },
  { name: "Publish GitHub Release", keys: ["name", "uses", "with"], values: { "uses" => "softprops/action-gh-release@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65", "with" => { "files" => "dist/*\n", "body_path" => "release-notes.md" } } },
  { name: "Setup Docker Buildx", keys: ["name", "uses", "with"], values: { "uses" => "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f", "with" => { "driver-opts" => "image=moby/buildkit:buildx-stable-1@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec" } } },
  { name: "Login to GHCR", keys: ["name", "uses", "with"], values: { "uses" => "docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9", "with" => { "registry" => "ghcr.io", "username" => "${{ github.actor }}", "password" => "${{ secrets.GITHUB_TOKEN }}" } } },
  { name: "Build and push runtime image", keys: ["name", "uses", "with"], values: { "uses" => "docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8", "with" => {
    "context" => ".",
    "file" => "docker/flowersec-runtime/Dockerfile",
    "platforms" => "linux/amd64,linux/arm64",
    "push" => true,
    "sbom" => true,
    "tags" => "ghcr.io/${{ github.repository_owner }}/flowersec-runtime:${{ steps.vars.outputs.version }}\nghcr.io/${{ github.repository_owner }}/flowersec-runtime:latest\n",
    "build-args" => "VERSION=v${{ steps.vars.outputs.version }}\nCOMMIT=${{ github.sha }}\nDATE=${{ steps.vars.outputs.date }}\n",
  } } },
  { name: "Publish npm package", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_VERSION" => "${{ steps.vars.outputs.version }}" } }, run_sha256: "c2cec9670487797dad340e84b95b5b39b22a1bae2394463ba4c3b7aa74b20f50" },
], "the unified release workflow release job")
validate_step_contracts(rust_steps, [
  { name: nil, keys: ["uses", "with"], values: checkout },
  { name: "Checkout release commit", keys: ["name", "id", "env", "run"], values: { "id" => "version", "env" => { "RELEASE_VERSION_INPUT" => "${{ inputs.version }}" } }, run_sha256: "ac06a1217c1f7df7c9e899d1fd91e3eb5a9c16f30aba50503028c62b391ac398" },
  { name: "Setup Rust", keys: ["name", "uses"], values: { "uses" => "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4" } },
  { name: "Validate release version facts", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_VERSION" => "${{ steps.version.outputs.version }}" } }, run_sha256: "9431ce4342dcd8f8af90607321f1ceb9e6e61c13f455b06acd242d96f53e0087" },
  { name: "Verify release tags", keys: ["name", "env", "run"], values: { "env" => { "RELEASE_VERSION" => "${{ steps.version.outputs.version }}" } }, run_sha256: "3e5e103b4b32e468d370d25613885b564a2f9f0dfebe2ced9b182a1691038830" },
  { name: "Check whether version is already published", keys: ["name", "id", "env", "run"], values: { "id" => "published", "env" => { "RELEASE_VERSION" => "${{ steps.version.outputs.version }}" } }, run_sha256: "712e2393343ff375abca1a8046cc8aa0b85be961fda34cc5125f7397248d5de0" },
  { name: "Authenticate to crates.io", keys: ["name", "if", "id", "uses"], values: { "if" => "steps.published.outputs.exists != 'true'", "id" => "auth", "uses" => "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18" } },
  { name: "Publish crate", keys: ["name", "if", "working-directory", "env", "run"], values: { "if" => "steps.published.outputs.exists != 'true'", "working-directory" => "flowersec-rust", "env" => { "CARGO_REGISTRY_TOKEN" => "${{ steps.auth.outputs.token }}" } }, run_sha256: "0990bd3b2f0dd14204dc600e8a8bce3fd1e41ab5a6404e75e59f7c41b49ea0d5" },
], "the Rust recovery workflow publish job")

reject_publication_before(release_steps, 8, "the unified release workflow")
reject_publication_before(rust_steps, 5, "the Rust recovery workflow")

release_setup, release_setup_index = require_named_step(release_steps, "Setup Rust", "the unified release workflow")
release_version, release_version_index = require_named_step(release_steps, "Validate release version facts", "the unified release workflow")
release_tags, release_tags_index = require_named_step(release_steps, "Verify all language tags point to this commit", "the unified release workflow")
require_step_field(release_setup, "uses", "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4", "the unified release workflow Setup Rust step")
require_step_field(release_version, "run", 'node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"', "the unified release workflow version facts step")
require_step_field(release_tags, "run", 'scripts/verify-release-tags.sh "$RELEASE_VERSION" "$GITHUB_SHA"', "the unified release workflow tag verification step")
[release_setup, release_version, release_tags].each_with_index do |step, index|
  require_unconditional(step, "the unified release workflow validation step #{index + 1}")
end
require_condition(release_setup_index < release_version_index && release_version_index < release_tags_index, "the unified release workflow must run Rust setup, version validation, and tag verification in order")

release_publication_steps = [
  "Build release artifacts",
  "Generate release notes",
  "Publish GitHub Release",
  "Build and push runtime image",
  "Publish npm package",
]
release_publication_steps.each do |name|
  step, index = require_named_step(release_steps, name, "the unified release workflow")
  require_unconditional(step, "the unified release workflow publication step #{name}")
  require_condition(release_version_index < index && release_tags_index < index, "the unified release workflow must validate versions and tags before every publication step, including #{name}")
end

rust_setup, rust_setup_index = require_named_step(rust_steps, "Setup Rust", "the Rust recovery workflow")
rust_version, rust_version_index = require_named_step(rust_steps, "Validate release version facts", "the Rust recovery workflow")
rust_tags, rust_tags_index = require_named_step(rust_steps, "Verify release tags", "the Rust recovery workflow")
rust_check, rust_check_index = require_named_step(rust_steps, "Check whether version is already published", "the Rust recovery workflow")
rust_auth, rust_auth_index = require_named_step(rust_steps, "Authenticate to crates.io", "the Rust recovery workflow")
rust_publish, rust_publish_index = require_named_step(rust_steps, "Publish crate", "the Rust recovery workflow")
require_step_field(rust_setup, "uses", "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4", "the Rust recovery workflow Setup Rust step")
require_step_field(rust_version, "run", 'node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"', "the Rust recovery workflow version facts step")
require_step_field(rust_tags, "run", 'scripts/verify-release-tags.sh "$RELEASE_VERSION" "$(git rev-parse HEAD)"', "the Rust recovery workflow tag verification step")
[rust_setup, rust_version, rust_tags].each_with_index do |step, index|
  require_unconditional(step, "the Rust recovery workflow validation step #{index + 1}")
end
require_unconditional(rust_check, "the Rust publication step that checks existing versions")
approved_condition = "steps.published.outputs.exists != 'true'"
require_condition_value(rust_auth, approved_condition, "the Rust publication step that authenticates")
require_condition_value(rust_publish, approved_condition, "the Rust publication step")
require_condition(
  rust_setup_index < rust_version_index && rust_version_index < rust_tags_index &&
    rust_tags_index < rust_check_index && rust_check_index < rust_auth_index &&
    rust_auth_index < rust_publish_index,
  "the Rust recovery workflow must validate versions and tags before every Rust publication step",
)

ci_policy_step, = require_named_step(ci_steps, "Check release workflow policy", "the hosted CI workflow")
require_step_field(ci_policy_step, "run", "scripts/check-release-workflow-policy.sh", "the hosted CI policy step")
require_unconditional(ci_policy_step, "the hosted CI policy step")

puts "verified structured release workflows"
rescue PolicyError => error
  $stderr.puts error.message
  exit 1
end
