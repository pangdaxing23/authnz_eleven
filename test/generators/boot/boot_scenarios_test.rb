# frozen_string_literal: true

require_relative "boot_test_case"
require_relative "../scenarios"

module AuthnzEleven
  # Tiers 3 & 4 over the shared scenario list (test/generators/scenarios.rb).
  # Each scenario builds once (generate + bundle), then two gates reuse that build:
  # assert_boots_cleanly (Tier 3 — zeitwerk) and assert_generated_suite_passes
  # (Tier 4 — the generated app's own test suite). Slow; opt-in via `rake test:boot`.
  class BootScenariosTest < BootTestCase
    # Per-scenario assertions beyond boot + suite-passes, run in the test instance.
    # Written into the app by the "kitchen_sink" check below.
    SUDO_AREA_TEST = <<~TEST
      require "test_helper"

      class SudoAreaTest < ActionDispatch::IntegrationTest
        setup { @user = users(:bob) }

        test "an area is closed until the bar is cleared, then open for the window" do
          post user_sign_in_path, params: { email: @user.email, password: "quilted-lantern-moss-97" }

          get vault_documents_path
          assert_redirected_to new_user_sudo_path
          follow_redirect!
          assert_includes response.body, "before opening the vault."

          post user_sudo_path, params: { sudo_password: "quilted-lantern-moss-97" }
          assert_redirected_to vault_documents_url

          follow_redirect!
          assert_response :success, "cleared the bar and still cannot enter the area"
          assert_equal "the vault", response.body

          # Still open on the next page, which is the whole point of a window.
          get vault_documents_path
          assert_response :success
        end

        test "the window closes" do
          post user_sign_in_path, params: { email: @user.email, password: "quilted-lantern-moss-97" }
          post user_sudo_path, params: { sudo_password: "quilted-lantern-moss-97",
                                         proceed_to_url: vault_documents_url }

          travel 16.minutes
          get vault_documents_path
          assert_response :redirect, "a stale stamp must not keep the area open"
        end
      end
    TEST

    HOLD_QUEUE_TEST = <<~TEST
      require "test_helper"

      class Users::HoldQueueTest < ActionDispatch::IntegrationTest
        setup { @user = users(:bob) }

        test "two requirements preserve and finally consume the interrupted destination" do
          @user.update_column(:password_changed_at, (UserAuth.password.maximum_age + 1.day).ago)
          UserAuth.session.concurrent_limit.times { @user.sessions.create! }

          get settings_path
          assert_redirected_to user_sign_in_path
          assert_equal settings_path, session[:interrupted_destination]

          post user_sign_in_path, params: { email: @user.email, password: "quilted-lantern-moss-97" }
          assert_redirected_to settings_path
          follow_redirect!
          assert_redirected_to settings_sessions_path
          assert_equal settings_path, session[:interrupted_destination]

          get edit_settings_password_path
          assert_response :success, "a gate's page skips every gate, so the two cannot bounce"

          delete settings_session_path(@user.sessions.order(:created_at).first)
          assert_redirected_to settings_path
          follow_redirect!
          assert_redirected_to edit_settings_password_path
          assert_equal settings_path, session[:interrupted_destination]

          patch settings_password_path, params: { password: "fresh-copper-orchard-82",
            password_confirmation: "fresh-copper-orchard-82", password_challenge: "quilted-lantern-moss-97" }
          assert_redirected_to settings_path
          assert_nil session[:interrupted_destination]
          follow_redirect!
          assert_response :success
        end

        test "a signed-out visit to a gate's page is still where you land" do
          @user.update_column(:password_changed_at, (UserAuth.password.maximum_age + 1.day).ago)

          get settings_sessions_path
          assert_equal settings_sessions_path, session[:interrupted_destination]

          post user_sign_in_path, params: { email: @user.email, password: "quilted-lantern-moss-97" }
          assert_redirected_to settings_sessions_path
          follow_redirect!
          assert_response :success

          get settings_path
          assert_redirected_to edit_settings_password_path
        end
      end
    TEST

    PORTAL_ISOLATION_TEST = <<~TEST
      require "test_helper"

      class PortalIsolationTest < ActionDispatch::IntegrationTest
        test "a merchant page runs nothing from the user's concern and shows the merchant's chrome" do
          post merchant_sign_in_path, params: { email: merchants(:bob).email, password: "quilted-lantern-moss-97" }
          get "/merchant/dashboard"

          assert_response :success
          assert_includes response.body, "merchant dashboard"
          assert_includes response.body, merchant_sign_out_path
          assert_not_includes response.body, user_sign_in_path
        end
      end
    TEST

    EXTRA_CHECKS = {
      # Users edit the generated code. A callback added to the default identity's
      # concern must not reach the namespaced identity's controllers, whose layout
      # carries their own nav rather than the default identity's.
      "portal_isolation" => lambda {
        concern = File.join(app_dir, "app/controllers/concerns/authentication.rb")
        callback = "    before_action { raise \"the user's concern ran on a merchant page\" }\n"
        File.write(concern, File.read(concern).sub("  included do\n", "  included do\n#{callback}"))

        File.write(File.join(app_dir, "app/controllers/merchants/dashboards_controller.rb"), <<~RUBY)
          class Merchants::DashboardsController < Merchants::BaseController
            def show = render(html: "merchant dashboard", layout: true)
          end
        RUBY
        routes = File.join(app_dir, "config/routes.rb")
        draw = "Rails.application.routes.draw do"
        File.write(routes,
                   File.read(routes).sub(draw, %(#{draw}\n  get "merchant/dashboard", to: "merchants/dashboards#show")))

        File.write(File.join(app_dir, "test/controllers/portal_isolation_test.rb"), PORTAL_ISOLATION_TEST)
        run_in_app!("bin/rails", "test", "test/controllers/portal_isolation_test.rb", timeout: 180)
      },

      "two_invitable" => lambda {
        routes = run_in_app!("bin/rails", "routes")
        assert_match(/\baccept_invitation\b/, routes)
        assert_match(/\brealtor_accept_invitation\b/, routes)
      },

      # The emitted starter tests each open ONE hold, so neither of them can see
      # what two open holds do to each other. This one opens both at once.
      "queued_holds" => lambda {
        File.write(File.join(app_dir, "test/controllers/users/hold_queue_test.rb"), HOLD_QUEUE_TEST)
        run_in_app!("bin/rails", "test", "test/controllers/users/hold_queue_test.rb", timeout: 180)
      },

      # No generated controller uses require_sudo_within — every shipped guard is an
      # action guard — so the area shape would otherwise ship untested. This writes a
      # guarded area into the app and drives the round trip the stock suite can't.
      "kitchen_sink" => lambda {
        FileUtils.mkdir_p(File.join(app_dir, "app/controllers/vault"))
        File.write(File.join(app_dir, "app/controllers/vault/documents_controller.rb"), <<~RUBY)
          class Vault::DocumentsController < ApplicationController
            require_sudo_within 15.minutes, message: "Please confirm it's you before opening the vault."

            def index = render(plain: "the vault")
          end
        RUBY

        routes = File.join(app_dir, "config/routes.rb")
        draw = "Rails.application.routes.draw do"
        vault = "  namespace :vault do\n    resources :documents, only: [ :index ]\n  end"
        File.write(routes, File.read(routes).sub(draw, "#{draw}\n#{vault}"))

        File.write(File.join(app_dir, "test/controllers/sudo_area_test.rb"), SUDO_AREA_TEST)
        run_in_app!("bin/rails", "test", "test/controllers/sudo_area_test.rb", timeout: 180)
      }
    }.freeze

    Scenarios::ALL.each do |name, invocations|
      define_method("test_boot_#{name}") do
        invocations.each { |flags| generate!(*flags) }
        bundle_install!
        assert_omakase_clean
        assert_boots_cleanly
        assert_generated_suite_passes
        instance_exec(&EXTRA_CHECKS[name]) if EXTRA_CHECKS[name]
      end
    end
  end
end
