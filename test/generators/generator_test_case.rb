# frozen_string_literal: true

require_relative "../dummy/config/environment"
require "rails/generators/test_case"
require "minitest/autorun"
require_relative "../../lib/generators/authnz_eleven/authnz_eleven_generator"

module AuthnzEleven
  # Shared base for fast, in-process generator tests: no bundle install, no
  # booting a second app, no subprocess. Runs the real Thor generator against
  # a scratch destination_root and asserts on the files it writes.
  #
  # This catches wrong file contents/paths but NOT cross-file constant
  # mismatches Zeitwerk would catch (a route's `module:` disagreeing with
  # where a controller file actually landed, say) — that class of bug needs a
  # real boot, which is what test/generators/boot_test_case.rb is for.
  class GeneratorTestCase < Rails::Generators::TestCase
    DUMMY_APP_ROOT = File.expand_path("../dummy", __dir__)

    # Copied into a fresh destination_root before every test, minus anything
    # that isn't source (logs, sqlite files, installed gems, secrets). The
    # generator expects a real app skeleton to exist already — Gemfile to
    # gsub/append to, app/controllers/application_controller.rb to inject
    # into, config/routes.rb to insert into — a bare empty dir isn't enough.
    SKELETON_ENTRIES = %w[
      Gemfile app bin config db lib Rakefile
    ].freeze

    tests AuthnzElevenGenerator
    destination File.expand_path("../../tmp/generator_tests", __dir__)

    setup :prepare_destination
    setup :seed_destination_from_dummy_app

    # All authnz_eleven boolean class_options, i.e. every --flag the
    # generator accepts, minus Thor's own built-ins (force/pretend/etc.) and
    # the string options (user_class/path/primary_key_type) which aren't
    # simple on/off flags. Used to drive matrix tests over "every flag" without
    # hand-maintaining a list that drifts from the generator's real options.
    def self.boolean_flags
      built_in = %i[skip_namespace skip_collision_check force pretend quiet skip]
      AuthnzElevenGenerator.class_options
                           .select { |_, opt| opt.type == :boolean }
                           .keys.map(&:to_sym) - built_in
    end

    # Rails' own run_generator appends --skip-bundle and --skip-bootsnap, which are
    # app-generator switches this generator has never accepted. They were harmless
    # while Thor silently ignored unknown ones; check_unknown_options! now refuses
    # them on purpose (a misspelled flag used to yield a build quietly missing the
    # feature), so the harness stops adding them.
    def run_generator(args = default_arguments, config = {})
      capture(:stdout) do
        generator_class.start(args, config.reverse_merge(destination_root: destination_root))
      end
    end

    private

    def seed_destination_from_dummy_app(root = destination_root)
      SKELETON_ENTRIES.each do |entry|
        source = File.join(DUMMY_APP_ROOT, entry)
        next unless File.exist?(source)

        FileUtils.cp_r(source, File.join(root, entry))
      end
    end
  end
end
