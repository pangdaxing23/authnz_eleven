# frozen_string_literal: true

require "minitest/autorun"

module AuthnzEleven
  # `require_sudo` reads its answer off
  # the guarded request itself, so a guarded action is only reachable if the form
  # that posts to it renders shared/_authnz_eleven_sudo_challenge. Miss that and
  # nothing fails loudly: the page renders, the button posts, and every attempt is
  # refused with the guard's own message.
  #
  # The emitted controller tests cannot see this. They send `sudo_password:` as a
  # param, which is exactly the param no form was producing.
  class SudoChallengeTest < Minitest::Test
    TEMPLATES_ROOT = File.expand_path("../../lib/generators/authnz_eleven/templates", __dir__)

    # Guarded controller => the view holding the form for every action it guards.
    # A map rather than a path convention because a controller's form may live
    # under any of its own views.
    FORMS = {
      "controllers/settings/emails_controller.rb.tt" => "erb/settings/emails/edit.html.erb.tt",
      "controllers/settings/api_tokens_controller.rb.tt" => "erb/settings/api_tokens/index.html.erb.tt",
      "controllers/settings/phones_controller.rb.tt" => "erb/settings/phones/edit.html.erb.tt",
      "controllers/settings/users_controller.rb.tt" => "erb/settings/users/show.html.erb.tt"
    }.freeze

    def test_every_guarded_action_poses_its_bar
      guarded_controllers.each do |controller|
        view = FORMS[controller]
        assert view, "#{controller} calls require_sudo but names no form:\n" \
                     "  add it to FORMS with the view whose form posts to the guarded action."

        assert_operator renders(view), :>=, guards(controller),
                        "#{view} renders the sudo challenge fewer times than #{controller} guards actions.\n" \
                        "Each guarded action needs its own form rendering identity.sudo_partial —\n" \
                        "a button_to cannot carry the answer, so the action becomes unreachable."
      end
    end

    # A stale entry would make the assertion above vacuous for a controller nobody
    # guards any more.
    def test_form_map_is_live
      assert_empty FORMS.keys - guarded_controllers,
                   "FORMS names controllers that no longer call require_sudo (remove them)."
    end

    private

    def guarded_controllers
      Dir.glob(File.join(TEMPLATES_ROOT, "controllers", "**", "*.tt"))
         .map { |path| path.sub("#{TEMPLATES_ROOT}/", "") }
         .select { |template| guards(template).positive? }
    end

    # Distinct guarded ACTIONS, not require_sudo lines: a template may declare the
    # same guard twice in two ERB branches. A guard with no `only:` covers the
    # controller, which is one action's worth of form either way.
    def guards(template)
      read(template).scan(/^\s*require_sudo\b[^\n]*/).map { |line| line[/only: :(\w+)/, 1] }.uniq.size
    end

    def renders(view)
      read(view).scan("identity.sudo_partial").size
    end

    def read(template) = File.read(File.join(TEMPLATES_ROOT, template))
  end
end
