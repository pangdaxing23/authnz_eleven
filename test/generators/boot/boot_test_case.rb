# frozen_string_literal: true

require "minitest/autorun"
require "bundler"
require "fileutils"
require "tmpdir"
require "open3"
require "timeout"
require "uri"
require "yaml"

module AuthnzEleven
  # Slow, end-to-end coverage: copies test/dummy to a scratch directory, runs
  # the real `bin/rails generate authnz_eleven` as a subprocess (exactly what
  # a user runs), bundles, and boot-checks the result with `zeitwerk:check`.
  #
  # This is the only layer that catches a route's `module:` disagreeing with
  # where a controller file actually landed — GeneratorTestCase (fast,
  # in-process) asserts file contents but never boots anything, so it can't
  # see that class of mismatch. Each scenario here takes several seconds
  # (subprocess boot + bundle install, even from a warm gem cache), so these
  # run separately from the fast suite — see the Rakefile.
  class BootTestCase < Minitest::Test
    DUMMY_APP_ROOT = File.expand_path("../../dummy", __dir__)
    # `test` carries the dummy's test/test_helper.rb (`fixtures :all`, etc.) so
    # the generator's emitted test_unit/* files — which `require "test_helper"`
    # — can run under Tier 4 (assert_generated_suite_passes).
    SKELETON_ENTRIES = %w[.rubocop.yml Gemfile app bin config db lib Rakefile test].freeze
    ADAPTER_GEMS = { "postgres" => "pg", "postgresql" => "pg", "trilogy" => "trilogy", "mysql2" => "mysql2" }.freeze

    def setup
      @scratch_dir = Dir.mktmpdir("authnz_eleven_boot_test")
      @app_dir = File.join(@scratch_dir, "app")
      FileUtils.mkdir_p(@app_dir)
      SKELETON_ENTRIES.each do |entry|
        source = File.join(DUMMY_APP_ROOT, entry)
        next unless File.exist?(source)

        FileUtils.cp_r(source, File.join(@app_dir, entry))
      end
      use_database(ENV["BOOT_DATABASE_URL"]) if ENV["BOOT_DATABASE_URL"]
    end

    def teardown
      FileUtils.remove_entry(@scratch_dir) if @scratch_dir
    end

    private

    attr_reader :app_dir

    # The URL names a server, not a database: each scratch app gets its own.
    def use_database(url)
      gemfile = File.join(app_dir, "Gemfile")
      File.write(gemfile, File.read(gemfile).sub(/^gem "sqlite3".*$/, %(gem "#{ADAPTER_GEMS.fetch(URI(url).scheme)}")))
      name = File.basename(@scratch_dir).tr("^a-zA-Z0-9", "_")
      config = %w[development test].to_h { |env| [env, { "url" => url, "database" => "#{name}_#{env}" }] }
      File.write(File.join(app_dir, "config/database.yml"), config.to_yaml)
    end

    # Runs a command inside the scratch app, under *its own* bundle (not the
    # outer authnz_eleven Gemfile) — exactly the environment a real user's
    # generated app runs in. The outer bundle is scrubbed (unbundled_env plus
    # unsetenv_others) rather than merged over: an inherited RUBYOPT
    # -rbundler/setup silently handed the child this gem's gem versions, so a
    # generated app that only breaks under a newer dependency stayed green.
    # Raises with full output on failure so a CI log shows the actual
    # Rails/bundler error, not just a boolean. Kills the whole process group on
    # timeout so a hung `bundle install` (e.g. stalled network) can't wedge the
    # suite indefinitely.
    def run_in_app!(*command, timeout: 120)
      env = Bundler.unbundled_env.merge(
        "BUNDLE_GEMFILE" => File.join(app_dir, "Gemfile"),
        "AUTHNZ_ELEVEN_GEM_ROOT" => File.expand_path("../../..", __dir__),
        "PARALLEL_WORKERS" => ENV["PARALLEL_WORKERS"]
      )
      output = +""
      pid = nil
      status =
        Open3.popen2e(env, *command, chdir: app_dir, pgroup: true, unsetenv_others: true) do |_in, out_err, wait_thr|
          pid = wait_thr.pid
          Timeout.timeout(timeout) { output << out_err.read }
          wait_thr.value
        end
      flunk "#{command.join(" ")} failed (exit #{status.exitstatus}) in #{app_dir}:\n#{output}" unless status.success?
      output
    rescue Timeout::Error
      Process.kill(-9, pid) if pid
      flunk "#{command.join(" ")} timed out after #{timeout}s in #{app_dir}"
    end

    def generate!(*flags)
      output = run_in_app!("bin/rails", "generate", "authnz_eleven", *flags)
      # Multi-identity additivity: a later identity
      # must never land on a file an earlier one wrote with different content. Thor
      # prints "conflict" and — non-interactively — keeps the incumbent, so the run
      # still "succeeds" while silently generating a half-wired identity. Catch it.
      refute_match(/^\s*conflict\s/, output, "generating #{flags.join(" ")} collided with an existing file")
      output
    end

    def bundle_install!
      run_in_app!("bundle", "install")
    end

    def assert_boots_cleanly
      output = run_in_app!("bin/rails", "zeitwerk:check")
      assert_match(/All is good!/, output)
    end

    def assert_omakase_clean
      run_in_app!("bundle", "exec", "rubocop")
    end

    # Tier 4: run the app's *own* generated test suite (the test_unit/* files
    # the generator emits) inside the built app — the only layer that proves a
    # flag combination produces *working* behavior (sign-in, verification,
    # lockout, …), not merely code that boots. sqlite's storage/ dir is
    # gitignored (so not in the copied skeleton) and each scenario is a fresh
    # copy with no schema.rb, so migrations run for real from the generated
    # migration files.
    def prepare_database!
      FileUtils.mkdir_p(File.join(app_dir, "storage"))
      run_in_app!("bin/rails", "db:create", "db:migrate", timeout: 180)
    end

    def assert_generated_suite_passes
      prepare_database!
      output = run_in_app!("bin/rails", "test", timeout: 300)
      # Require ≥1 run and zero failures/errors, so an empty "0 runs" (no tests
      # found — a misconfigured app) can't pass as a silent green.
      assert_match(/[1-9]\d* runs, \d+ assertions, 0 failures, 0 errors/, output,
                   "generated app's own test suite did not pass cleanly:\n#{output}")
    end
  end
end
