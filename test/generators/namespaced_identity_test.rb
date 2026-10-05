# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  # Regression coverage for a real session's worth of bugs: generating a
  # second, --namespaced identity alongside the default one produced files whose
  # class/module declarations didn't match where Zeitwerk (or the routes)
  # actually expected them — a route nested under `module: :admins` resolving
  # to a controller literally named `Admin::...`, an authentication concern
  # module hardcoded to `Authentication` regardless of its file name, etc.
  # These assertions pin the specific naming agreement that broke.
  class NamespacedIdentityTest < GeneratorTestCase
    def test_second_namespaced_identity_stays_consistent_with_its_own_routes
      run_generator %w[--password --registration=open --email]
      run_generator %w[
        --passkey --sudoable --trackable --timeoutable --bannable --registration=invite-only
        --namespaced --user-class=Admin --email
      ]

      # The settings controllers must live under the SAME module the namespaced
      # route block nests everything else in (Admins::, plural, from
      # identity.controller_module) — not the singular "admin" that
      # settings_helper_prefix uses for route helpers, which the routes never
      # actually point at for controller resolution. (This identity is
      # passkey-only, so it has no settings/passwords_controller — the passkeys
      # one exercises the same nesting property.)
      assert_file "app/controllers/admins/settings/passkeys_controller.rb",
                  /\Aclass Admins::Settings::PasskeysController < Admins::SettingsController\b/
      assert_file "app/controllers/admins/settings_controller.rb",
                  /\Aclass Admins::SettingsController < Admins::BaseController\b/

      # The authentication concern's module name must match its own file name
      # (admins/authentication.rb -> Admins::Authentication), not a hardcoded
      # "Authentication" left over from the default identity.
      assert_file "app/controllers/concerns/admins/authentication.rb", /\Amodule Admins::Authentication\b/

      # A namespaced identity's own InvitationsController must be namespaced to
      # match where it's actually filed (app/controllers/admins/). The route that
      # points at it lives outside the identity's main scope block, so it must
      # carry its own path prefix (else it collides with the incumbent's identical
      # "invitations/accept" path) and name the namespaced controller in full in
      # `to:` (an inline module: option alongside a string to: doesn't namespace —
      # it leaks in as a param and the bare InvitationsController answers instead).
      assert_file "app/controllers/admins/invitations_controller.rb",
                  /\Aclass Admins::InvitationsController < Admins::BaseController\b/
      assert_file "config/routes.rb",
                  %r{get\s+"admin/invitations/accept", to: "admins/invitations#show", as: :admin_accept_invitation}
      # Without teams an existing account has nothing to accept, so there is no PATCH.
      assert_file "config/routes.rb" do |routes|
        refute_match %r{patch\s+"admin/invitations/accept"}, routes
      end

      # Failure-path redirects inside a namespaced identity's own controllers
      # should stay inside that identity's own scope, not the app's global root.
      assert_file "app/controllers/admins/invitations_controller.rb", /redirect_to admin_root_path/
    end
  end
end
