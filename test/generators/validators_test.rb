# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  # The generator's fail-fast validators (see authnz_eleven_generator.rb:60+)
  # raise Rails::Generators::Error, but Thor::Base#start rescues that itself
  # and prints the message rather than letting it propagate as a Ruby
  # exception — so these assert against captured output, not assert_raises.
  class ValidatorsTest < GeneratorTestCase
    def test_no_principal_is_rejected
      output = capture(:stderr) { run_generator %w[--password] }

      assert_match(/No identifier was selected/, output)
      assert_no_file "app/models/user.rb"
    end

    def test_no_authentication_strategy_is_rejected
      output = capture(:stderr) { run_generator %w[--email] }

      assert_match(/No sign-in method was selected/, output)
      assert_no_file "app/models/user.rb"
    end

    def test_none_is_not_a_principal_mode
      email_output = capture(:stderr) { run_generator %w[--password --email=none --username] }
      phone_output = capture(:stderr) { run_generator %w[--password --phone=none --username] }

      assert_match(/--email=none isn't valid/, email_output)
      assert_match(/--phone=none isn't valid/, phone_output)
    end

    def test_security_notifications_require_email
      output = capture(:stderr) { run_generator %w[--password --username --security-notifications] }

      assert_match(/--security-notifications needs --email/, output)
      assert_no_file "app/mailers/user_mailer.rb"
    end

    def test_sms_code_requires_an_explicit_phone
      output = capture(:stderr) { run_generator %w[--sms-code --email] }

      assert_match(/--sms-code needs --phone/, output)
      assert_no_file "app/controllers/users/sms_sessions_controller.rb"
    end

    # --sms-code texts the code to the number on the account, so as the only door it
    # needs one to be guaranteed.
    def test_sms_code_as_the_only_door_with_an_optional_phone_is_rejected
      output = capture(:stderr) { run_generator %w[--sms-code --phone=optional] }

      assert_match(/--sms-code is the only sign-in method/, output)
      assert_no_file "app/controllers/users/sms_sessions_controller.rb"
    end

    def test_sms_code_with_an_optional_phone_is_allowed_beside_another_door
      run_generator %w[--password --sms-code --phone=optional --email]

      assert_file "app/controllers/users/sms_sessions_controller.rb"
    end

    # A door is an authentication strategy, but its phone principal stays explicit.
    def test_sms_code_with_a_phone_satisfies_the_strategy_requirement
      run_generator %w[--sms-code --phone]

      assert_file "app/controllers/users/sms_sessions_controller.rb"
      assert_file "app/models/user/sms_challengeable.rb"
      # The required phone makes the door usable, and a plain unique index guards it.
      migration = Dir.glob(File.join(destination_root, "db/migrate/*_create_users.rb")).sole
      assert_match(/t\.string :phone, null: false, index: \{ unique: true \}$/,
                   File.read(migration))
    end

    # A bare --phone / --email reads as "required". Thor would otherwise hand the
    # flag its own name as the value and the build would die on a typo message.
    def test_bare_principal_flags_mean_required
      run_generator %w[--password --phone --email]

      migration = Dir.glob(File.join(destination_root, "db/migrate/*_create_users.rb")).sole

      assert_match(/t\.string :phone/, File.read(migration))
      assert_match(/t\.string :email, +null: false/, File.read(migration))
      generator = AuthnzElevenGenerator.new([], %w[--password --phone --email])
      assert generator.send(:principals).phone.required?
    end

    # ",permanent" removes the self-serve change surface. It only reads as a rule
    # where the value is there from the start, which is what these three refuse.
    def test_optional_permanent_is_rejected
      output = capture(:stderr) { run_generator %w[--password --email=optional,permanent --no-contactable --username] }

      assert_match(/--email=optional,permanent isn't supported/, output)
      assert_no_file "app/models/user.rb"
    end

    def test_permanent_phone_is_allowed_when_registration_verifies_it_before_the_account
      run_generator %w[--password --email --phone=required,permanent]

      assert_file "app/models/user.rb"
      assert_file "app/models/pending_registration.rb"
      migration = Dir.glob(File.join(destination_root, "db/migrate/*_create_pending_registrations.rb")).sole
      assert_match(/t\.datetime :phone_verified_at/, File.read(migration))
    end

    def test_an_unknown_modifier_is_rejected
      output = capture(:stderr) { run_generator %w[--password --email=required,permanant] }

      assert_match(/--email=required,permanant isn't valid/, output)
      assert_no_file "app/models/user.rb"
    end

    # The user's call: --no-verifiable freezes an unproved address, so say so and
    # build it. The column stays writable, so an admin or a console can still fix one.
    def test_permanent_with_no_verifiable_warns_but_builds
      output = run_generator %w[--password --email=required,permanent --no-verifiable]

      assert_match(/the value is never verified/, output)
      assert_file "app/models/user.rb"
      assert_no_file "app/controllers/settings/emails_controller.rb"
    end

    def test_deferred_password_with_nothing_before_the_second_page_is_rejected
      [
        %w[--username --password=deferred],
        %w[--email --password=deferred --no-verifiable],
        %w[--username --email=optional --password=deferred --no-contactable]
      ].each do |flags|
        output = capture(:stderr) { run_generator flags }

        assert_match(/--password=deferred asks for the password after/, output, flags.join(" "))
        assert_no_file "app/models/user.rb"
      end
    end

    def test_deferred_password_beside_a_passkey_offers_the_choice
      run_generator %w[--username --password=deferred --passkey]

      assert_file "app/views/users/credential_enrollments/show.html.erb", /Create a passkey/
    end

    def test_deferred_password_when_every_sign_up_proves_a_channel
      run_generator %w[--email=optional --phone=optional --password=deferred]

      assert_file "app/models/pending_registration.rb"
    end

    def test_sudo_with_nothing_to_ask_for_is_rejected
      [
        %w[--magic-link --email --sudoable],
        %w[--omniauth --email --sudoable],
        %w[--sms-code --phone --sudoable]
      ].each do |flags|
        output = capture(:stderr) { run_generator flags }

        assert_match(/--sudoable needs a password, a passkey/, output, flags.join(" "))
        assert_no_file "app/models/user.rb"
      end
    end

    def test_coy_without_verification_is_rejected
      output = capture(:stderr) { run_generator %w[--password --email --coy --no-verifiable] }

      assert_match(/--coy needs verification/, output)
      assert_no_file "app/models/user.rb"
    end

    def test_sudo_rides_an_authenticator_in_a_passwordless_build
      run_generator %w[--magic-link --email --second-factor=totp --sudoable]

      assert_file "app/controllers/concerns/authentication/sudoable.rb", /when :totp/
    end

    def test_second_identity_without_namespace_is_rejected
      run_generator %w[--password --email]
      output = capture(:stderr) { run_generator %w[--password --email --user-class=Realtor] }

      assert_match(/must be\n?\s*generated with --namespaced/, output)
      assert_no_file "app/models/realtor.rb"
    end

    def test_user_class_colliding_with_an_existing_namespace_is_rejected
      run_generator %w[--password --email]
      # Simulate an app that already defines the Admin::* controller namespace on
      # disk (from any feature that claims it). A later run picking
      # --user-class=Admin would make Admin a model constant colliding with that
      # namespace — the thing under test (see validate_no_constant_collision!).
      FileUtils.mkdir_p(File.join(destination_root, "app/controllers/admin"))
      File.write(File.join(destination_root, "app/controllers/admin/dashboard_controller.rb"),
                 "class Admin::DashboardController; end\n")

      output = capture(:stderr) do
        run_generator %w[--password --email --namespaced --user-class=Admin]
      end

      assert_match(/--user-class=Admin can't be used/, output)
      assert_no_file "app/models/admin.rb"
    end

    def test_empty_namespace_directory_does_not_false_positive
      # A stray empty app/controllers/admin/ (no .rb files inside) defines no
      # autoload entry, so it can't actually collide — this is the false
      # positive from earlier in the session that the directory-existence-only
      # check produced.
      FileUtils.mkdir_p(File.join(destination_root, "app/controllers/admin"))

      run_generator %w[--password --email --namespaced --user-class=Admin]

      assert_file "app/models/admin.rb"
    end

    def test_admin_dashboard_and_user_class_admin_in_the_same_run_is_rejected
      output = capture(:stderr) do
        run_generator %w[--password --email --admin-dashboard --user-class=Admin]
      end

      assert_match(/--admin-dashboard and --user-class=Admin can't be combined/, output)
      assert_no_file "app/models/admin.rb"
    end
  end
end
