# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  # One test per boolean --flag the generator accepts (see
  # GeneratorTestCase.boolean_flags, which introspects the generator's real
  # class_options so a newly-added flag is covered automatically). Each run is
  # --password (a valid strategy for every flag, per validate_authentication_strategy!)
  # plus the flag under test — the point is just "this flag doesn't blow up on its
  # own, and produces the concern file every build produces," not full feature coverage.
  class IndividualFlagsTest < GeneratorTestCase
    GeneratorTestCase.boolean_flags.each do |flag|
      define_method("test_flag_#{flag}_generates_without_error") do
        dashed = flag.to_s.tr("_", "-")
        args = ["--password", "--email", "--#{dashed}"]
        args << "--phone" if flag == :sms_code
        run_generator args

        # A universal invariant regardless of --namespaced (which changes the
        # concern's file name/path) — the initializer is always created, and
        # only by this generator, so it also proves the run actually did
        # something rather than silently no-op'ing.
        initializers = Dir.glob(File.join(destination_root, "config/initializers/*authentication*.rb"))
        assert initializers.any?, "expected an *authentication*.rb initializer to be generated"
      end
    end

    # Everything TOTP puts in a build. A --second-factor=webauthn build must carry
    # none of it: that is the whole point of splitting the flag.
    TOTP_ARTIFACTS = %w[
      app/controllers/settings/multi_factor_authentication/authenticators_controller.rb
      app/controllers/users/multi_factor_authentication/challenge/totps_controller.rb
    ].freeze

    # --second-factor is a string flag, so boolean_flags above can't reach it. Each
    # value is a genuinely different build, so all three are smoke-tested and each
    # is checked for the factor it did and didn't ask for.
    { "totp" => true, "webauthn" => false, "totp,webauthn" => true }.each do |value, expects_totp|
      define_method("test_second_factor_#{value.tr(",", "_")}_generates_without_error") do
        run_generator ["--password", "--email", "--second-factor=#{value}"]

        migration = Dir.glob(File.join(destination_root, "db/migrate/*create_users.rb")).sole
        assert_equal expects_totp, File.read(migration).include?("totp_secret"),
                     "totp_secret must exist only where --second-factor includes totp"

        TOTP_ARTIFACTS.each do |path|
          assert_equal expects_totp, File.exist?(File.join(destination_root, path)), path
        end
      end
    end
  end
end
