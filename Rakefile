# frozen_string_literal: true

require "bundler/gem_tasks"
require "minitest/test_task"

# Tier 1 (unit): the gem's own tests, including the value objects under
# test/authnz_eleven/ (Principal/Principals — and Layer A predicate truth
# tables as they land). Excludes test/generators (its own bundle context —
# see below) and test/dummy/test (the dummy Rails app's own generated tests,
# which are fixtures, not part of this gem's suite).
Minitest::TestTask.create do |t|
  t.test_globs = FileList["test/*_test.rb", "test/authnz_eleven/**/*_test.rb"]
end

require "rubocop/rake_task"

RuboCop::RakeTask.new

def run_boot_suite(env = {})
  script = 'Dir.glob("test/generators/boot/*_test.rb").each { |f| require_relative f }'
  system(env, "bundle", "exec", "ruby", "-Itest", "-e", script) ||
    abort("test:boot failed")
end

# In-memory data and one test worker per app: the Docker VM's disk and memory
# cannot hold a database per worker for every scenario.
BOOT_DATABASES = {
  postgresql: { image: "postgres:17", data: "/var/lib/postgresql/data", ports: "55432:5432",
                env: "POSTGRES_PASSWORD=pw", ready: %w[pg_isready -h 127.0.0.1],
                url: "postgres://postgres:pw@127.0.0.1:55432?gssencmode=disable" },
  mysql: { image: "mysql:8.4", data: "/var/lib/mysql", ports: "53306:3306",
           env: "MYSQL_ROOT_PASSWORD=pw", ready: ["mysql", "-h127.0.0.1", "-uroot", "-ppw", "-e", "SELECT 1"],
           url: "trilogy://root:pw@127.0.0.1:53306" }
}.freeze

namespace :test do
  desc "Run the generator test suite (fast, in-process file/content assertions against test/dummy)"
  task :generators do
    env = { "BUNDLE_GEMFILE" => File.expand_path("test/dummy/Gemfile", __dir__) }
    script = 'Dir.glob("test/generators/*_test.rb").each { |f| require_relative f }'
    system(env, "bundle", "exec", "ruby", "-Itest", "-Ilib", "-e", script) ||
      abort("test:generators failed")
  end

  desc "Run the generator boot suite (slow: subprocess generate + bundle install + zeitwerk:check per scenario)"
  task(:boot) { run_boot_suite }

  namespace :boot do
    BOOT_DATABASES.each do |name, db|
      desc "Run the boot suite against #{name} in a throwaway Docker container"
      task name do
        container = "authnz_eleven_boot_#{name}"
        sh "docker", "run", "-d", "--rm", "--name", container, "--tmpfs", db[:data], "-e", db[:env],
           "-p", db[:ports], db[:image]
        sleep 1 until system("docker", "exec", container, *db[:ready], out: File::NULL, err: File::NULL)
        run_boot_suite("BOOT_DATABASE_URL" => db[:url], "PARALLEL_WORKERS" => "1")
      ensure
        system("docker", "rm", "-f", container, out: File::NULL, err: File::NULL)
      end
    end
  end
end

desc "Run unit tests, fast generator tests, and rubocop. Slow boot checks: rake test:boot"
task default: %i[test test:generators rubocop]
