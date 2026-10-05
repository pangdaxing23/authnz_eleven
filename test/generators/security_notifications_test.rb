# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  class SecurityNotificationsTest < GeneratorTestCase
    def test_the_flag_wires_every_security_change
      run_generator %w[--password=optional --passkey --omniauth --recoverable --deadboltable
                       --second-factor=totp,webauthn,sms --admin-dashboard --bannable
                       --phone --security-notifications --email]

      assert_file "app/mailers/user_mailer.rb", /def security_notification/
      assert_file "app/views/user_mailer/security_notification.html.erb", /If this wasn't you/
      assert_file "app/mailers/user_mailer.rb", /def self\.send_security_notification/
      assert_file "app/controllers/concerns/authentication.rb" do |source|
        refute_includes source, "send_security_notification"
      end
      assert_file "test/controllers/users/security_notifications_test.rb"

      expected_events.each do |path, events|
        assert_file(path) do |source|
          events.each { |event| assert_includes source, "UserMailer.send_security_notification(:#{event}" }
        end
      end
    end

    def test_unverified_channel_changes_send_notifications_after_the_write
      run_generator %w[--password --phone --no-verifiable --security-notifications --email]

      assert_file "app/controllers/settings/emails_controller.rb",
                  /send_security_notification\(:email_changed, to: old_email\)/
      assert_file "app/controllers/settings/phones_controller.rb", /send_security_notification\(:phone_changed\)/
    end

    def test_a_namespaced_identity_uses_its_own_mailer
      run_generator %w[--password --namespaced --user-class=Realtor --security-notifications --email]

      assert_file "app/mailers/realtor_mailer.rb", /def security_notification/
      assert_file "app/mailers/realtor_mailer.rb", /def self\.send_security_notification/
      assert_file "app/controllers/realtors/settings/passwords_controller.rb",
                  /RealtorMailer\.send_security_notification\(/
      assert_file "app/views/realtor_mailer/security_notification.html.erb"
    end

    def test_a_build_without_the_flag_has_no_security_notification_code
      run_generator %w[--password --email]

      assert_file "app/mailers/user_mailer.rb" do |source|
        refute_includes source, "security_notification"
      end
      assert_no_file "app/views/user_mailer/security_notification.html.erb"
      assert_file "app/mailers/user_mailer.rb" do |source|
        refute_includes source, "send_security_notification"
      end
    end

    private

    def expected_events
      {
        "app/controllers/settings/passwords_controller.rb" => %i[password_changed password_set password_removed],
        "app/controllers/users/password_resets_controller.rb" => %i[password_reset],
        "app/controllers/settings/passkeys_controller.rb" => %i[passkey_added passkey_removed],
        "app/controllers/settings/multi_factor_authentication/security_keys_controller.rb" =>
          %i[security_key_added security_key_removed],
        "app/controllers/settings/multi_factor_authentication/authenticators_controller.rb" =>
          %i[authenticator_enabled authenticator_disabled],
        "app/controllers/settings/multi_factor_authentication/sms_controller.rb" =>
          %i[sms_mfa_enabled sms_mfa_disabled],
        "app/controllers/settings/multi_factor_authentication/recovery_codes_controller.rb" =>
          %i[recovery_codes_generated],
        "app/controllers/users/omniauth_controller.rb" => %i[connected_account_linked],
        "app/controllers/settings/omniauth_identities_controller.rb" => %i[connected_account_unlinked],
        "app/controllers/users/email_verifications_controller.rb" => %i[email_changed],
        "app/controllers/settings/phone_verifications_controller.rb" => %i[phone_changed],
        "app/controllers/settings/sessions_controller.rb" => %i[session_revoked],
        "app/controllers/settings/users_controller.rb" => %i[account_deleted],
        "app/controllers/admin/users_controller.rb" =>
          %i[sessions_revoked_by_admin second_factor_reset_by_admin deadbolt_cleared_by_admin
             account_suspended account_restored account_deleted]
      }
    end
  end
end
