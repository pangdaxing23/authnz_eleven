# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  class ImpedimentsTest < GeneratorTestCase
    CONCERN = "app/controllers/concerns/authentication.rb"

    def test_gates_are_before_actions_in_declaration_order
      run_generator %w[--password --registration=open --max-sessionable=prompt --password-rotatable --email]

      assert_file_includes CONCERN,
                           "    before_action :require_authentication\n" \
                           "    before_action :require_session_within_limit, if: :authenticated?\n" \
                           "    before_action :require_fresh_password, if: :authenticated?\n",
                           "skip_before_action :require_session_within_limit, :require_fresh_password, " \
                           "**options, raise: false",
                           "  def require_fresh_password\n" \
                           "    return if Current.user.password_fresh?\n\n" \
                           "    remember_interrupted_destination\n" \
                           "    redirect_to edit_settings_password_path, alert: \"Your password has expired. " \
                           "Choose a new one to continue.\", status: :see_other\n",
                           "def interrupted_destination(otherwise:)"
      assert_file_includes "app/controllers/settings/sessions_controller.rb",
                           "skip_impediments",
                           "redirect_to interrupted_destination(otherwise: settings_sessions_path)"
      assert_file_includes "app/controllers/settings/passwords_controller.rb",
                           "skip_impediments",
                           "redirect_to interrupted_destination(otherwise: edit_settings_password_path)"
      assert_file_includes "app/controllers/users/sessions_controller.rb", "skip_impediments only: :destroy"
    end

    def test_gates_stand_down_while_impersonating
      run_generator %w[--password --admin-dashboard --impersonatable --password-rotatable --email]

      assert_file_includes CONCERN,
                           "before_action :require_fresh_password, if: :authenticated?, unless: :impersonating?"
    end

    def test_a_build_without_gates_has_no_gate_code
      run_generator %w[--password --registration=open --email]

      assert_file CONCERN do |source|
        refute_includes source, "skip_impediments"
        assert_includes source, "    before_action :require_authentication\n    helper_method :authenticated?"
      end
      assert_file "app/controllers/settings_controller.rb" do |source|
        assert_equal "class SettingsController < ApplicationController\nend\n", source
      end
      assert_file "app/controllers/users/sessions_controller.rb" do |source|
        refute_includes source, "skip_impediments"
      end
    end

    def test_the_team_gate_spares_the_admin_settings_and_invitation_areas
      run_generator %w[--password --registration=open-and-invites --teams=session --admin-dashboard --email]

      assert_file_includes "app/controllers/admin_controller.rb", "skip_before_action :require_team"
      assert_file_includes "app/controllers/settings_controller.rb",
                           "class SettingsController < ApplicationController\n  skip_before_action :require_team"
      assert_file_includes "app/controllers/invitations_controller.rb", "skip_before_action :require_team"
      assert_file_includes "app/controllers/teams_controller.rb",
                           "skip_impediments",
                           "redirect_to interrupted_destination(otherwise: root_path)"
    end

    def test_namespaced_settings_controllers_inherit_their_own_settings_base
      run_generator %w[--password --namespaced --user-class=Realtor --email]

      assert_file_includes "app/controllers/realtors/settings_controller.rb",
                           "class Realtors::SettingsController < Realtors::BaseController"
      assert_file_includes "app/controllers/realtors/settings/dashboard_controller.rb",
                           "class Realtors::Settings::DashboardController < Realtors::SettingsController"
    end

    # reset_session drops the whole session, the saved destination with it, so
    # there is no per-key delete at sign-out to keep in step with the key's name.
    def test_sign_out_abandons_the_saved_destination
      run_generator %w[--password --password-rotatable --email]

      assert_file CONCERN do |source|
        assert_match(/def terminate_current_session\n(?:.*\n)*?    reset_session\n  end/, source)
      end
    end

    def test_mfa_enrollment_delivers_codes_before_acknowledgment_navigates
      run_generator %w[--password --second-factor=totp,webauthn --admin-dashboard --email]

      assert_file "config/routes.rb", /post :complete, on: :collection/
      assert_file_includes "app/controllers/settings/multi_factor_authentication/recovery_codes_controller.rb",
                           "def complete", "redirect_to interrupted_destination("
      assert_file_includes "app/views/settings/multi_factor_authentication/recovery_codes/create.html.erb",
                           "button_to \"I've saved them\", complete_settings_mfa_recovery_codes_path"
      assert_enrollment_renders_codes "security_keys_controller.rb"
      assert_enrollment_renders_codes "authenticators_controller.rb"
    end

    # A gate's page may pose a sudo bar (adding a security key does), and the sudo
    # page is where that bar lives. Gate it and the two bounce off each other forever.
    def test_the_sudo_page_skips_every_gate
      run_generator %w[--password --registration=open --second-factor=totp --admin-dashboard
                       --sudoable --password-rotatable --teams=session --email]

      assert_file_includes "app/controllers/users/sudos_controller.rb", "skip_impediments"
      assert_file_includes CONCERN,
                           "skip_before_action :require_admin_mfa, :require_fresh_password, :require_team, " \
                           "**options, raise: false"
    end

    def test_easy_dev_login_drops_the_admin_mfa_gate
      run_generator %w[--password --second-factor=totp --admin-dashboard --easy-dev-login --email]

      assert_file_includes "app/controllers/concerns/authentication/easy_dev_login.rb",
                           "skip_before_action :require_admin_mfa unless Authentication::EasyDevLogin.mfa_required?"
    end

    def test_namespaced_identities_isolate_the_saved_destination
      run_generator %w[--password --namespaced --user-class=Realtor --email]

      assert_file "app/controllers/concerns/realtors/authentication.rb" do |source|
        assert_includes source, "session[:realtor_interrupted_destination]"
        refute_includes source, "session[:interrupted_destination]"
      end
    end

    private

    def assert_enrollment_renders_codes(controller)
      path = "app/controllers/settings/multi_factor_authentication/#{controller}"
      assert_file_includes path, "flash.delete(:alert)",
                           "render \"settings/multi_factor_authentication/recovery_codes/create\""
    end

    def assert_file_includes(path, *snippets)
      assert_file path do |source|
        snippets.each { |snippet| assert_includes source, snippet }
      end
    end
  end
end
