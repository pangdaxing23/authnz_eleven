# frozen_string_literal: true

require "minitest/autorun"
require "fileutils"
require "tmpdir"
require "rails/generators"
require_relative "scenarios"
require_relative "../../lib/generators/authnz_eleven/authnz_eleven_generator"

module AuthnzEleven
  # Every template must be built by at least one scenario, so nothing is silently
  # untested. Renders each scenario in
  # Scenarios::ALL in-process while intercepting the generator's
  # template/migration_template/copy_file calls (so migrations are tracked too),
  # then asserts every .tt under templates/ is built by something. Fast — no
  # bundle, no boot.
  #
  # Reads the same list BootScenariosTest boots, so a template is either
  # booted-and-run by that suite or red here. When it goes red: add a scenario
  # that builds the template, or a SKIP_PREFIXES entry with a reason.
  class ScenarioCompletenessTest < Minitest::Test
    TEMPLATES_ROOT = File.expand_path("../../lib/generators/authnz_eleven/templates", __dir__)
    DUMMY_APP_ROOT = File.expand_path("../dummy", __dir__)
    SKELETON = %w[Gemfile app bin config db lib Rakefile].freeze

    # Template subtrees deliberately left untested — no scenario builds them, on
    # purpose. Each prefix carries a reason. Subtracted from the denominator, and
    # guarded two ways below: a prefix matching NO template (stale/renamed dir) or
    # a skipped template a scenario actually builds (the skip is hiding something)
    # both fail the test.
    SKIP_PREFIXES = {}.freeze

    def test_every_template_is_built_by_a_scenario
      built = Scenarios::ALL.each_with_object(Set.new) do |(name, invocations), set|
        set.merge(render_and_record(name, invocations))
      end

      all_templates = Dir.glob(File.join(TEMPLATES_ROOT, "**", "*.tt"))
                         .map { |p| p.sub("#{TEMPLATES_ROOT}/", "") }
      skipped, tested = all_templates.partition { |t| SKIP_PREFIXES.keys.any? { |p| t.start_with?(p) } }

      unbuilt = tested.to_set - built
      assert_empty unbuilt.sort,
                   "These templates are built by NO scenario (add a scenario that builds them, " \
                   "or a SKIP_PREFIXES entry with a reason):\n  #{unbuilt.sort.join("\n  ")}"

      # Staleness guard 1: every skip prefix must still match at least one template.
      dead = SKIP_PREFIXES.keys.reject { |p| all_templates.any? { |t| t.start_with?(p) } }
      assert_empty dead,
                   "These SKIP_PREFIXES match no template (remove them):\n  #{dead.join("\n  ")}"

      # Staleness guard 2: a skipped template a scenario actually builds means the
      # skip is hiding a now-tested path — narrow or drop the prefix.
      hidden = skipped.to_set & built
      assert_empty hidden.sort,
                   "These templates are skipped but ARE built by a scenario (narrow SKIP_PREFIXES):\n  " \
                   "#{hidden.sort.join("\n  ")}"
    end

    private

    def render_and_record(name, invocations)
      recorded = []
      Dir.mktmpdir("scenario_#{name}") do |dir|
        SKELETON.each do |entry|
          src = File.join(DUMMY_APP_ROOT, entry)
          FileUtils.cp_r(src, File.join(dir, entry)) if File.exist?(src)
        end
        recorder = recorder_module(recorded)
        invocations.each do |flags|
          gen = AuthnzElevenGenerator.new([], flags)
          gen.destination_root = dir
          gen.singleton_class.prepend(recorder)
          silence { gen.invoke_all }
        end
      end
      recorded.select { |s| s.end_with?(".tt") }
    end

    # Prepended onto each generator instance: records the source path of every
    # rendered template, and neutralizes shell-outs (install_javascript runs
    # `bin/importmap pin ...`, which we must not execute in-process).
    def recorder_module(sink)
      Module.new do
        define_method(:template) do |source, *rest, &blk|
          sink << source.to_s
          super(source, *rest, &blk)
        end
        define_method(:migration_template) do |source, *rest, &blk|
          sink << source.to_s
          super(source, *rest, &blk)
        end
        define_method(:copy_file) do |source, *rest, &blk|
          sink << source.to_s
          super(source, *rest, &blk)
        end
        define_method(:run) { |*_args, **_opts| nil }
      end
    end

    def silence
      original = $stdout
      $stdout = File.open(File::NULL, "w")
      yield
    ensure
      $stdout.close
      $stdout = original
    end
  end
end
