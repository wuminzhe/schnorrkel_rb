# frozen_string_literal: true

require "bundler/gem_tasks"
require "thermite/tasks"

Thermite::Tasks.new

task default: %w[thermite:build]

desc "Run Rust & Ruby testsuites"
task test: ["thermite:build", "thermite:test"] do
end
